use std::io::Result;

use trojan::socks5::*;

#[tokio::main]
async fn main() -> Result<()> {
    Socks5Listener::listen("127.0.0.1:1081").await
}
