use std::net::SocketAddr;

use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::error::Result;
use crate::socks5::{Socks5Acceptor, Socks5Target, TargetConnector};
use crate::trojan::TrojanConnector;

impl Socks5Acceptor {
    pub async fn associate_udp(self) -> Result<()> {
        let mut tcp = self.stream;
        let target = &self.buf[3..];
        let mut local = tcp.local_addr()?;
        local.set_port(0);
        let mut client = tcp.peer_addr()?;
        let target_len = target.len();
        let client_port = u16::from_be_bytes([target[target_len - 2], target[target_len - 1]]);
        client.set_port(client_port);
        let udp_socket = UdpSocket::bind(&local).await?;
        udp_socket.connect(&client).await?;

        let mut connector: TrojanConnector<(&str, u16)> = TargetConnector::from(3, &target)?;
        eprintln!("{} == {} (udp)", client, udp_socket.local_addr()?);

        let reply = match udp_socket.local_addr()? {
            SocketAddr::V4(x) => [
                b"\x05\x00\x00\x01".as_ref(),
                x.ip().octets().as_ref(),
                x.port().to_be_bytes().as_ref(),
            ]
            .concat(),
            SocketAddr::V6(x) => [
                b"\x05\x00\x00\x04".as_ref(),
                x.ip().octets().as_ref(),
                x.port().to_be_bytes().as_ref(),
            ]
            .concat(),
        };
        tcp.write_all(&reply).await?;
        let upstream = match connector.connect().await {
            Ok(_) => connector.connected()?,
            Err(e) => {
                tcp.write_all(&[b"\x05\x01\x00", target].concat()).await?;
                return Err(e);
            }
        };
        let (mut receiver, mut sender) = udp_socket.split();
        let (mut upstream_receiver, mut upstream_sender) = split(upstream);

        let t0 = async {
            tcp.read(&mut [0]).await?;
            Ok(())
        };

        let t1 = async {
            let mut buf = vec![0; 1461];
            loop {
                let n = receiver.recv(&mut buf[1..]).await?;
                let offset = Socks5Target::target_len(&buf[4..])?;
                eprintln!(
                    "{} -> {} (udp)",
                    client,
                    Socks5Target::try_parse(&buf[4..4 + offset])?
                );
                buf.copy_within(4..4 + offset, 0);
                buf[offset..offset + 2]
                    .copy_from_slice(((n - offset - 3) as u16).to_be_bytes().as_ref());
                buf[offset + 2..offset + 4].copy_from_slice(b"\r\n");
                upstream_sender.write_all(&buf[..n + 1]).await?;
            }
        };

        let t2 = async {
            let mut buf = Vec::with_capacity(1460);
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
                sender.send(&buf[1..]).await?;
            }
        };

        tokio::select! {
            r0 = t0 => {
                r0
            },
            r1 = t1 => {
                r1
            },
            r2 = t2 => {
                r2
            },
        }
    }
}
