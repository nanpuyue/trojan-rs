use trojan::error::Result;
use trojan::socks5::Socks5Listener;

#[tokio::main]
async fn main() -> Result<()> {
    let mut socks5_proxy = Socks5Listener::listen("127.0.0.1:1081").await?;
    socks5_proxy.handle_incoming().await
}