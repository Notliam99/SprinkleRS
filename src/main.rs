//! HTTP Server with JSON POST handler
//!
//! Go to 192.168.71.1 to test

use core::convert::TryInto;
use std::sync::{Arc, Mutex};

use embedded_svc::{
    http::{server::asynch::Connection, Headers, Method},
    io::{Read, Write},
    utils::http,
    wifi::{self, AccessPointConfiguration, AuthMethod},
};

use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    http::server::EspHttpServer,
    nvs::EspDefaultNvsPartition,
    wifi::{BlockingWifi, EspWifi},
};
use esp_idf_svc::{
    hal::{
        gpio::{Gpio8, Output, PinDriver},
        prelude::Peripherals,
    },
    http::{client::Request, server::Handler},
};

use log::*;

use serde::{Deserialize, Serialize};
use serde_json::json;

const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASS");
const ACCESSPOINT_MODE: &str = env!("ACCESSPOINT_MODE");
static INDEX_HTML: &str = include_str!("http_server_page.html");

// Max payload length
const MAX_LEN: usize = 128;

// Need lots of stack to parse JSON
const STACK_SIZE: usize = 10240;

// Wi-Fi channel, between 1 and 11
const CHANNEL: u8 = 11;

#[derive(Deserialize)]
struct FormData<'a> {
    first_name: &'a str,
    age: u32,
    birthplace: &'a str,
}

#[derive(Deserialize, Serialize, Default)]
struct Zones {
    zone1: bool,
    zone2: bool,
    zone3: bool,
    zone4: bool,
}

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // Setup Wifi

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;

    match ACCESSPOINT_MODE {
        "true" => wifi_ap(&mut wifi),
        _ => connect_wifi(&mut wifi),
    }?;

    let zone1_pin_mutex = Arc::new(Mutex::new(PinDriver::output(peripherals.pins.gpio18)?));
    let zone2_pin_mutex = Arc::new(Mutex::new(PinDriver::output(peripherals.pins.gpio19)?));
    let zone3_pin_mutex = Arc::new(Mutex::new(PinDriver::output(peripherals.pins.gpio20)?));
    let zone4_pin_mutex = Arc::new(Mutex::new(PinDriver::output(peripherals.pins.gpio21)?));

    let led_pin = PinDriver::output(peripherals.pins.gpio15)?;

    let mutex = Arc::new(Mutex::new(led_pin));

    let zone_mutex = Arc::new(Mutex::new(Zones {
        ..Default::default()
    }));

    let zone_mutex1 = Arc::clone(&zone_mutex);

    let mut server = create_server()?;

    server.fn_handler("/", Method::Get, move |req| {
        let mut led = mutex.lock().unwrap();

        led.toggle()?;

        req.into_ok_response()?
            .write_all(INDEX_HTML.as_bytes())
            .map(|_| ())
    })?;

    server.fn_handler("/zones", Method::Get, move |req| {
        let status = zone_mutex1.lock().unwrap();

        let json_status = serde_json::to_string(&*status).unwrap();

        req.into_response(200, None, &[("Content-Type", "application/json")])?
            .write_all(json_status.as_bytes())
    })?;

    server.fn_handler::<anyhow::Error, _>("/zones", Method::Post, move |mut req| {
        let len = req.content_len().unwrap_or(0) as usize;

        if len > MAX_LEN {
            req.into_status_response(413)?
                .write_all("Request too big".as_bytes())?;
            return Ok(());
        }

        let mut zones = zone_mutex.lock().unwrap();

        let mut zone1_pin = zone1_pin_mutex.lock().unwrap();
        let mut zone2_pin = zone2_pin_mutex.lock().unwrap();
        let mut zone3_pin = zone3_pin_mutex.lock().unwrap();
        let mut zone4_pin = zone4_pin_mutex.lock().unwrap();

        let mut buf = vec![0; len];
        req.read_exact(&mut buf)?;

        match serde_json::from_slice::<Zones>(&buf) {
            Ok(zones_value) => {
                match zones_value.zone1 {
                    true => zone1_pin.set_high()?,
                    false => zone1_pin.set_low()?,
                };

                match zones_value.zone2 {
                    true => zone2_pin.set_high()?,
                    false => zone2_pin.set_low()?,
                };

                match zones_value.zone3 {
                    true => zone3_pin.set_high()?,
                    false => zone3_pin.set_low()?,
                };

                match zones_value.zone1 {
                    true => zone4_pin.set_high()?,
                    false => zone4_pin.set_low()?,
                };

                *zones = zones_value;

                req.into_response(200, None, &[("Content-Type", "application/json")])?
                    .write_all(
                        json!({"message": "Sucsessfuly applied"})
                            .to_string()
                            .as_bytes(),
                    )
            }
            Err(_) => Ok(req
                .into_status_response(401)?
                .write_all("Json Error".as_bytes())?),
        };

        Ok(())
    })?;

    // Keep wifi and the server running beyond when main() returns (forever)
    // Do not call this if you ever want to stop or access them later.
    // Otherwise you can either add an infinite loop so the main task
    // never returns, or you can move them to another thread.
    // https://doc.rust-lang.org/stable/core/mem/fn.forget.html
    core::mem::forget(wifi);
    core::mem::forget(server);

    // Main task no longer needed, free up some memory
    Ok(())
}

fn wifi_ap(wifi: &mut BlockingWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    // If instead of creating a new network you want to serve the page
    // on your local network, you can replace this configuration with
    // the client configuration from the http_client example.
    let wifi_configuration = wifi::Configuration::AccessPoint(AccessPointConfiguration {
        ssid: SSID.try_into().unwrap(),
        ssid_hidden: false,
        auth_method: AuthMethod::WPA2Personal,
        password: PASSWORD.try_into().unwrap(),
        channel: CHANNEL,
        ..Default::default()
    });

    wifi.set_configuration(&wifi_configuration)?;

    wifi.start()?;
    info!("Wifi started");

    // If using a client configuration you need
    // to connect to the network with:
    //
    //  ```
    //  wifi.connect()?;
    //  info!("Wifi connected");
    // ```

    wifi.wait_netif_up()?;
    info!("Wifi netif up");

    info!(
        "Created Wi-Fi with WIFI_SSID `{}` and WIFI_PASS `{}`",
        SSID, PASSWORD
    );

    Ok(())
}

fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    let wifi_configuration: wifi::Configuration =
        wifi::Configuration::Client(wifi::ClientConfiguration {
            ssid: SSID.try_into().unwrap(),
            bssid: None,
            auth_method: AuthMethod::WPA2Personal,
            password: PASSWORD.try_into().unwrap(),
            channel: None,
            ..Default::default()
        });

    wifi.set_configuration(&wifi_configuration)?;

    wifi.start()?;
    info!("Wifi started");

    wifi.connect()?;
    info!("Wifi connected");

    wifi.wait_netif_up()?;
    info!("Wifi netif up");

    Ok(())
}

fn create_server() -> anyhow::Result<EspHttpServer<'static>> {
    let server_configuration = esp_idf_svc::http::server::Configuration {
        stack_size: STACK_SIZE,
        ..Default::default()
    };

    Ok(EspHttpServer::new(&server_configuration)?)
}
