use std::fmt::{Display, Formatter};
use std::io::Result;
use std::net::{SocketAddrV4, SocketAddrV6};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::stream::StreamExt;

use crate::error::io_error;

pub struct Socks5Listener {
    listener: TcpListener,
}

pub enum Socks5Addr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String),
}

impl Display for Socks5Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(s) => s.fmt(f),
            Self::V6(s) => s.fmt(f),
            Self::Domain(s) => s.fmt(f),
        }
    }
}

impl Socks5Addr {
    unsafe fn parse_ipv4(data: &[u8]) -> Self {
        Self::V4(SocketAddrV4::new(
            (*(data.as_ptr() as *const [u8; 4])).into(),
            u16::from_be_bytes([data[4], data[5]]),
        ))
    }

    unsafe fn parse_ipv6(data: &[u8]) -> Self {
        Self::V6(SocketAddrV6::new(
            (*(data.as_ptr() as *const [u8; 16])).into(),
            u16::from_be_bytes([data[16], data[17]]),
            0,
            0,
        ))
    }

    fn try_parse_domain(data: &[u8]) -> Result<Self> {
        let len = data.len();
        let domain = match String::from_utf8(data[1..len - 2].into()) {
            Ok(s) => s,
            Err(e) => return Err(io_error(&format!("Invalid Domain: {}!", e))),
        };
        let port = u16::from_be_bytes([data[len - 2], data[len - 1]]).to_string();
        Ok(Self::Domain(domain + ":" + &port))
    }

    pub async fn connect(&self) -> Result<TcpStream> {
        match self {
            Self::V4(s) => TcpStream::connect(s).await,
            Self::V6(s) => TcpStream::connect(s).await,
            Self::Domain(s) => TcpStream::connect(s).await,
        }
    }
}

impl Socks5Listener {
    pub async fn listen<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub async fn handle_incoming(&mut self) -> Result<()> {
        async move {
            let mut incoming = self.listener.incoming();
            while let Some(s) = incoming.next().await.transpose()? {
                eprintln!("accepted connection from {}", s.peer_addr().unwrap());
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_accept(s).await {
                        eprintln!("handle_accept err: {}", e)
                    }
                });
            }
            Ok(())
        }
        .await
    }

    async fn handle_accept(mut c: TcpStream) -> Result<()> {
        let mut buf = Vec::with_capacity(512);
        let mut n;
        let mut len = 0;

        while {
            n = c.read_buf(&mut buf).await?;
            n > 0
        } {
            if buf.len() >= 2 {
                len = 2 + buf[1] as usize;
            }

            if len > 0 && buf.len() >= len {
                break;
            }
        }
        if len == 0 || buf.len() != len || buf[0] != 5 {
            return Err(io_error("Invalid Request!"));
        }

        if !buf[2..].contains(&0) {
            c.write_all(b"\x05\xff").await?;
            return Err(io_error("No Supported Authentication Method!"));
        }

        c.write_all(b"\x05\x00").await?;

        buf.clear();
        len = 0;

        while {
            n = c.read_buf(&mut buf).await?;
            n > 0
        } {
            if len == 0 && buf.len() >= 5 {
                len = match buf[3] {
                    1 => 10,
                    4 => 22,
                    3 => 7 + buf[4] as usize,
                    _ => return Err(io_error("Invalid Address Type!")),
                };
            }

            if len > 0 && buf.len() >= len {
                break;
            }
        }

        if len == 0 || buf.len() != len || buf[0] != 5 || buf[2] != 0 {
            return Err(io_error("Invalid Request!"));
        }

        if buf[1] != 1 {
            return Err(io_error("Unsupported Request Command!"));
        }

        let addr = match buf[3] {
            1 => unsafe { Socks5Addr::parse_ipv4(&buf[4..]) },
            4 => unsafe { Socks5Addr::parse_ipv6(&buf[4..]) },
            3 => Socks5Addr::try_parse_domain(&buf[4..])?,
            _ => unreachable!(),
        };

        eprintln!("connect {}...", addr);
        let s = addr.connect().await?;
        // TODO
        c.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            .await?;

        link_tcpstream(c, s).await
    }
}

async fn link_tcpstream(a: TcpStream, b: TcpStream) -> Result<()> {
    let (ar, aw) = &mut io::split(a);
    let (br, bw) = &mut io::split(b);

    tokio::select! {
        r1 = io::copy(ar, bw) => {
            r1.map(drop)
        },
        r2 = io::copy(br, aw) => {
            r2.map(drop)
        }
    }
}
