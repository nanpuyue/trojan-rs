#![feature(maybe_uninit_extra)]
#![feature(maybe_uninit_ref)]

use std::path::Path;

use clap::{App, Arg};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::stream::StreamExt;

use trojan::config::{Config, CONFIG};
use trojan::error::Result;
use trojan::socks5::Socks5Listener;
use trojan::tls::set_tls_connector;
use trojan::trojan::TrojanConnector;

async unsafe fn set_config<P: AsRef<Path>>(path: P) -> Result<()> {
    let mut file = File::open(path).await?;
    let json = &mut String::new();
    file.read_to_string(json).await?;

    let config = serde_json::from_str::<Config>(json)?;
    CONFIG.write(config);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("trojan-rs")
        .version("0.1.0")
        .author("南浦月 <nanpuyue@gmail.com>")
        .about("Rust implementation of the trojan protocol")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("CONFIG")
                .help("Specify the config file")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    unsafe {
        set_config(config_path).await?;
        set_tls_connector()?;
    }

    let local = unsafe {
        let addr = CONFIG.get_ref().local_addr.as_ref();
        let port = CONFIG.get_ref().local_port;
        (addr, port)
    };
    let mut listener = Socks5Listener::listen(local).await?;

    while let Some((acceptor, client)) = listener.next().await.transpose()? {
        tokio::spawn(async move {
            if let Err(e) = acceptor
                .connect_target::<TrojanConnector<(&str, u16)>>()
                .await
            {
                eprintln!("{} => {}", client, e)
            }
        });
    }

    Ok(())
}
