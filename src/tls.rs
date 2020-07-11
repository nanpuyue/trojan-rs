use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_native_tls::{TlsConnector, TlsStream};

use crate::error::Result;

pub struct TrojanConnector<A: ToSocketAddrs> {
    addr: A,
    domain: String,
}

impl<A: ToSocketAddrs> TrojanConnector<A> {
    pub fn new(addr: A, domain: String) -> Self {
        Self { addr, domain }
    }

    pub async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let tls_connector = TlsConnector::from(
            native_tls::TlsConnector::builder()
                // FIXME
                .danger_accept_invalid_certs(true)
                .build()?,
        );

        let tcpstream = TcpStream::connect(&self.addr).await?;
        Ok(tls_connector.connect(&self.domain, tcpstream).await?)
    }
}
