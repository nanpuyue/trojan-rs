use std::fmt::{Display, Formatter};
use std::io::Result;
use std::net::{SocketAddrV4, SocketAddrV6};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::channel;

use crate::error::io_error;

pub struct Socks5Listener;

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
    pub async fn listen<A: ToSocketAddrs>(addr: A) -> Result<()> {
        let mut listener = TcpListener::bind(addr).await?;
        let (mut accept_sender, mut accept_receiver) = channel::<TcpStream>(32);

        let acceptor = async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        eprintln!("received connection from {}", addr);
                        if let Err(e) = accept_sender.send(socket).await {
                            eprintln!("accept_sender err: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("accept connection err: {}", e);
                        break;
                    }
                }
            }
        };

        let connector = async move {
            loop {
                if let Some(s) = accept_receiver.recv().await {
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_accept(s).await {
                            eprintln!("handle_accept err: {}", e)
                        }
                    });
                }
            }
        };

        if let Err(e) = tokio::select! {
            r1 = tokio::spawn(acceptor) => r1,
            r2 = tokio::spawn(connector) => r2,
        } {
            Err(io_error(&e.to_string()))
        } else {
            Ok(())
        }
    }

    async fn handle_accept(mut c: TcpStream) -> Result<()> {
        eprintln!("handle_accept: {}", c.peer_addr()?);
        let mut buf = Vec::with_capacity(1024);
        let mut n: usize = 0;

        // TODO
        loop {
            n += c.read_buf(&mut buf).await?;
            if n >= 2 {
                break;
            }
        }
        c.write_all(b"\x05\x00").await?;

        unsafe { buf.set_len(512) };
        let mut data = Vec::with_capacity(512);
        let mut data_len = None;

        while {
            n = c.read(&mut buf).await?;
            n > 0
        } {
            data.append(&mut buf[..n].into());

            if data_len.is_none() && data.len() >= 5 {
                data_len = Some(match data[3] {
                    1 => 10,
                    4 => 22,
                    3 => 7 + data[4] as usize,
                    _ => return Err(io_error("Invalid Address Type!")),
                });
            }

            if let Some(len) = data_len {
                if data.len() >= len {
                    break;
                }
            }
        }

        if data_len.is_none() || data.len() != data_len.unwrap() || data[0] != 5 || data[2] != 0 {
            return Err(io_error("Invalid Request!"));
        }

        if data[1] != 1 {
            return Err(io_error("Unsupported Authentication Method!"));
        }

        let addr = match data[3] {
            1 => unsafe { Socks5Addr::parse_ipv4(&data[4..]) },
            4 => unsafe { Socks5Addr::parse_ipv6(&data[4..]) },
            3 => Socks5Addr::try_parse_domain(&data[4..])?,
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
