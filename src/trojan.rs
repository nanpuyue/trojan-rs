use std::sync::Once;

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;

use crate::config::CONFIG;
use crate::error::Result;
use crate::socks5::{Socks5Target, TargetConnector};
use crate::tls::{TlsConnector, TrojanTlsConnector, TLS_CONNECTOR};
use crate::util::ToHex;

type TlsStream = <TlsConnector as TrojanTlsConnector>::Stream;

pub struct TrojanConnector<'a, A: ToSocketAddrs> {
    remote: A,
    domain: &'a str,
    target: Socks5Target,
    stream: Option<TlsStream>,
    request: Vec<u8>,
}

impl<A: ToSocketAddrs> TrojanConnector<'_, A> {
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
impl TargetConnector for TrojanConnector<'_, (&'_ str, u16)> {
    type Stream = TlsStream;

    async fn connect(&mut self) -> Result<()> {
        let mut stream = unsafe {
            TLS_CONNECTOR
                .get_ref()
                .connect(&self.remote, &self.domain)
                .await?
        };
        stream.write_all(&self.request).await?;
        self.stream = Some(stream);

        Ok(())
    }

    fn connected(mut self) -> Result<Self::Stream> {
        Ok(self.stream.take()?)
    }

    fn from(target: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        unsafe {
            let addr = CONFIG.get_ref().remote_addr.as_ref();
            let port = CONFIG.get_ref().remote_port;
            let remote = (addr, port);

            let sni = CONFIG.get_ref().ssl.client().sni.as_str();
            let domain = if sni.is_empty() { addr } else { sni };

            Ok(Self {
                remote,
                domain,
                target: Socks5Target::try_parse(target)?,
                stream: None,
                request: Self::trojan_request(1, target),
            })
        }
    }

    fn target(&self) -> &Socks5Target {
        &self.target
    }
}
