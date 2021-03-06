#![feature(maybe_uninit_extra)]

use std::sync::Arc;

use clap::{App, Arg};
use tokio_stream::StreamExt;

use trojan::config::{set_config, CONFIG};
use trojan::error::Result;
use trojan::route::Router;
use trojan::socks5::Socks5Listener;
use trojan::tls::set_tls_connector;
#[cfg(target_family = "unix")]
use trojan::util::set_rlimit_nofile;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("trojan-rs")
        .version("0.2.0")
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
        .arg(
            Arg::with_name("route")
                .short("r")
                .long("route")
                .value_name("ROUTE")
                .help("Specify the route rules file")
                .takes_value(true)
                .required(false),
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    unsafe {
        set_config(config_path)?;
        set_tls_connector()?;
    }

    let router = match matches.value_of("route") {
        Some(x) => Some(Arc::new(Router::load(x)?)),
        None => None,
    };

    let local = unsafe {
        let addr = CONFIG.assume_init_ref().local_addr.as_ref();
        let port = CONFIG.assume_init_ref().local_port;
        (addr, port)
    };
    let mut listener = Socks5Listener::listen(local).await?;

    #[cfg(target_family = "unix")]
    set_rlimit_nofile(4096).unwrap_or_else(|e| eprintln!("set RLIMIT_NOFILE failed: {}", e));

    while let Some((acceptor, client)) = listener.next().await.transpose()? {
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = acceptor.accept(router.as_deref()).await {
                eprintln!("{} => {}", client, e)
            }
        });
    }

    Ok(())
}
