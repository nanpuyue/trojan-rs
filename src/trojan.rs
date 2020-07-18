use std::sync::Once;

use async_trait::async_trait;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::ToSocketAddrs;

use crate::config::CONFIG;
use crate::error::Result;
use crate::socks5::{Socks5Target, Socks5UdpClient, TargetConnector};
use crate::tls::{TlsConnector, TrojanTlsConnector, TLS_CONNECTOR};
use crate::util::{sha224, ToHex};

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
            let password = CONFIG.get_ref().password[0].as_bytes();
            PASSWORD_HASH = sha224(password).to_hex().into();
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
    type Upstream = TlsStream;
    type UdpUpstream = TlsStream;

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

    fn connected(mut self) -> Result<Self::Upstream> {
        Ok(self.stream.take()?)
    }

    async fn udp_bind(&mut self) -> Result<()> {
        self.connect().await
    }

    fn udp_upstream(self) -> Result<Self::UdpUpstream> {
        self.connected()
    }

    async fn forward_udp(client: Socks5UdpClient, upstream: Self::UdpUpstream) -> Result<()> {
        let client_addr = client.client_addr();

        let (client_receiver, client_sender) = &mut client.connect().await?.split();
        let (upstream_receiver, upstream_sender) = &mut split(upstream);

        let t1 = async {
            let mut buf = vec![0; 1472];
            loop {
                let udp_len = client_receiver.recv(&mut buf[1..]).await?;
                let offset = Socks5Target::target_len(&buf[4..])?;
                eprintln!(
                    "{} -> {} (udp)",
                    client_addr,
                    Socks5Target::try_parse(&buf[4..4 + offset])?
                );
                buf.copy_within(4..4 + offset, 0);
                buf[offset..offset + 2]
                    .copy_from_slice(((udp_len - offset - 3) as u16).to_be_bytes().as_ref());
                buf[offset + 2..offset + 4].copy_from_slice(b"\r\n");
                upstream_sender.write_all(&buf[..udp_len + 1]).await?;
            }
        };

        let t2 = async {
            let mut buf = Vec::new();
            loop {
                buf.resize(2, 0);
                upstream_receiver.read_exact(&mut buf).await?;
                let offset = Socks5Target::target_len(&buf)?;
                buf.resize(offset + 4, 0);
                upstream_receiver.read_exact(&mut buf[2..]).await?;

                let length = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                buf.resize(offset + 4 + length as usize, 0);
                upstream_receiver.read_exact(&mut buf[offset + 4..]).await?;
                buf.copy_within(0..offset, 4);
                buf[1..4].fill(0);
                client_sender.send(&buf[1..]).await?;
            }
        };

        tokio::select! {
            r1 = t1 => {
                r1
            },
            r2 = t2 => {
                r2
            },
        }
    }

    fn from(command: u8, target: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        unsafe {
            let addr = CONFIG.get_ref().remote_addr.as_ref();
            let port = CONFIG.get_ref().remote_port;
            let remote = (addr, port);

            let sni = CONFIG.get_ref().ssl.client()?.sni.as_str();
            let domain = if sni.is_empty() { addr } else { sni };

            Ok(Self {
                remote,
                domain,
                target: Socks5Target::try_parse(target)?,
                stream: None,
                request: Self::trojan_request(command, target),
            })
        }
    }

    fn target(&self) -> &Socks5Target {
        &self.target
    }
}
