use std::sync::Once;

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_native_tls::{TlsConnector, TlsStream};

use crate::config::CONFIG;
use crate::error::Result;
use crate::socks5::{parse_target, Socks5Target, TargetConnector};
use crate::util::ToHex;

pub struct TrojanConnector<A: ToSocketAddrs> {
    remote: A,
    domain: String,
    target: Socks5Target,
    stream: Option<TlsStream<TcpStream>>,
    request: Vec<u8>,
}

impl<A: ToSocketAddrs> TrojanConnector<A> {
    fn trojan_request(command: u8, target: &[u8]) -> Vec<u8> {
        static mut PASSWORD_HASH: Vec<u8> = Vec::new();
        static HASH_PASSWORD: Once = Once::new();
        HASH_PASSWORD.call_once(|| unsafe {
            let password = &CONFIG.get_ref().password[0];
            let mut sha224 = Sha224::new();
            sha224.update(password);
            PASSWORD_HASH = sha224.finalize().to_hex().into();
        });

        let mut buf = Vec::new();
        buf.extend_from_slice(unsafe { &PASSWORD_HASH });
        buf.extend_from_slice("\r\n".as_ref());
        buf.push(command);
        buf.extend_from_slice(target);
        buf.extend_from_slice("\r\n".as_ref());

        buf
    }
}

#[async_trait]
impl TargetConnector for TrojanConnector<(&'_ str, u16)> {
    type Stream = TlsStream<TcpStream>;

    async fn connect(&mut self) -> Result<()> {
        let tls_connector = TlsConnector::from(
            native_tls::TlsConnector::builder()
                // FIXME
                .danger_accept_invalid_certs(true)
                .build()?,
        );

        let tcpstream = TcpStream::connect(&self.remote).await?;
        self.stream = Some(tls_connector.connect(&self.domain, tcpstream).await?);

        Ok(())
    }

    async fn send_request(&mut self) -> Result<()> {
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&self.request)
            .await?;
        Ok(())
    }

    unsafe fn new(target: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let addr = CONFIG.get_ref().remote_addr.as_ref();
        let port = CONFIG.get_ref().remote_port;
        let remote = (addr, port);

        Ok(Self {
            remote,
            domain: CONFIG.get_ref().ssl.client().sni.to_owned(),
            target: parse_target(target)?,
            stream: None,
            request: Self::trojan_request(1, target),
        })
    }

    fn target(&self) -> &Socks5Target {
        &self.target
    }

    fn take_stream(&mut self) -> Option<Self::Stream> {
        self.stream.take()
    }
}
