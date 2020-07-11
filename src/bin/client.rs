#![feature(maybe_uninit_extra)]
#![feature(maybe_uninit_ref)]

use std::path::Path;

use tokio::fs::File;
use tokio::io::AsyncReadExt;
use trojan::config::{Config, CONFIG};
use trojan::error::Result;
use trojan::socks5::Socks5Listener;

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
    unsafe { set_config("client.json").await? };

    let local = unsafe {
        let addr = CONFIG.get_ref().local_addr.as_ref();
        let port = CONFIG.get_ref().local_port;
        (addr, port)
    };
    let mut socks5_proxy = Socks5Listener::listen(local).await?;
    socks5_proxy.handle_incoming().await
}
