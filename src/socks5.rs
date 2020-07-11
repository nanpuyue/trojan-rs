use std::fmt::{Display, Formatter};
use std::net::{SocketAddrV4, SocketAddrV6};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::stream::StreamExt;

use crate::error::Result;
use crate::util::link_stream;

#[async_trait]
pub trait TargetConnector: Send {
    type Stream: AsyncRead + AsyncWrite;

    async fn connect(&mut self) -> Result<()>;

    async fn send_request(&mut self) -> Result<()> {
        Ok(())
    }

    fn take_stream(&mut self) -> Option<Self::Stream>;
}

pub struct Socks5Listener {
    listener: TcpListener,
}

struct Socks5Stream {
    stream: TcpStream,
    buf: Vec<u8>,
    target: Vec<u8>,
}

pub enum Socks5Target {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String),
}

pub struct DirectConnector {
    target: Socks5Target,
    stream: Option<TcpStream>,
}

impl From<Socks5Target> for DirectConnector {
    fn from(target: Socks5Target) -> Self {
        Self {
            target,
            stream: None,
        }
    }
}

impl Display for Socks5Target {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(s) => s.fmt(f),
            Self::V6(s) => s.fmt(f),
            Self::Domain(s) => s.fmt(f),
        }
    }
}

impl Socks5Target {
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
            Err(e) => return Err(format!("Invalid Domain: {}!", e).into()),
        };
        let port = u16::from_be_bytes([data[len - 2], data[len - 1]]).to_string();
        Ok(Self::Domain(domain + ":" + &port))
    }
}

#[async_trait]
impl TargetConnector for DirectConnector {
    type Stream = TcpStream;

    async fn connect(&mut self) -> Result<()> {
        self.stream = Some(match &self.target {
            Socks5Target::V4(s) => TcpStream::connect(s).await?,
            Socks5Target::V6(s) => TcpStream::connect(s).await?,
            Socks5Target::Domain(s) => TcpStream::connect(s).await?,
        });

        Ok(())
    }

    fn take_stream(&mut self) -> Option<Self::Stream> {
        self.stream.take()
    }
}

impl Socks5Stream {
    fn new(stream: TcpStream) -> Self {
        Socks5Stream {
            stream,
            buf: Vec::with_capacity(512),
            target: Vec::new(),
        }
    }

    async fn authenticate(&mut self) -> Result<()> {
        let mut n;
        let mut len = 0;

        self.buf.clear();
        while {
            n = self.stream.read_buf(&mut self.buf).await?;
            n > 0
        } {
            if self.buf.len() >= 2 {
                len = 2 + self.buf[1] as usize;
            }

            if len > 0 && self.buf.len() >= len {
                break;
            }
        }
        if len == 0 || self.buf.len() != len || self.buf[0] != 5 {
            return Err("Invalid Request!".into());
        }

        if !self.buf[2..].contains(&0) {
            self.stream.write_all(b"\x05\xff").await?;
            return Err("No Supported Authentication Method!".into());
        }

        self.stream.write_all(b"\x05\x00").await?;
        Ok(())
    }

    unsafe fn parse_target(&self) -> Result<Socks5Target> {
        Ok(match self.target[0] {
            1 => Socks5Target::parse_ipv4(&self.target[1..]),
            4 => Socks5Target::parse_ipv6(&self.target[1..]),
            3 => Socks5Target::try_parse_domain(&self.target[1..])?,
            _ => unreachable!(),
        })
    }

    async fn handle_command(mut self) -> Result<()> {
        let mut n;
        let mut len = 0;

        self.buf.clear();
        while {
            n = self.stream.read_buf(&mut self.buf).await?;
            n > 0
        } {
            if len == 0 && self.buf.len() >= 5 {
                len = match self.buf[3] {
                    1 => 10,
                    4 => 22,
                    3 => 7 + self.buf[4] as usize,
                    _ => {
                        self.stream.write_all(b"\x05\x08").await?;
                        return Err("Invalid Address Type!".into());
                    }
                };
            }

            if len > 0 && self.buf.len() >= len {
                break;
            }
        }

        if len == 0 || self.buf.len() != len || self.buf[0] != 5 || self.buf[2] != 0 {
            return Err("Invalid Request!".into());
        }

        if self.buf[1] != 1 {
            self.stream.write_all(b"\x05\x07").await?;
            return Err("Unsupported Request Command!".into());
        }

        self.target = self.buf.split_off(3);

        self.handle_connect::<DirectConnector>().await
    }

    async fn handle_connect<C: TargetConnector + From<Socks5Target>>(mut self) -> Result<()> {
        let target = unsafe { self.parse_target()? };
        eprintln!("connect {}...", target);

        let connector = &mut C::from(target);
        match connector.connect().await {
            Ok(_) => {
                self.stream
                    .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    .await?;
                connector.send_request().await?;
                link_stream(self.stream, connector.take_stream().unwrap()).await
            }
            Err(e) => {
                self.stream
                    .write_all(&[b"\x05\x01\x00", &self.buf[3..]].concat())
                    .await?;
                Err(e)
            }
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
        async {
            let mut incoming = self.listener.incoming();
            while let Some(stream) = incoming.next().await.transpose()? {
                eprintln!("accepted connection from {}", stream.peer_addr().unwrap());
                tokio::spawn(async {
                    if let Err(e) = async {
                        let mut socks5_stream = Socks5Stream::new(stream);
                        socks5_stream.authenticate().await?;
                        socks5_stream.handle_command().await
                    }
                    .await
                    {
                        eprintln!("handle incoming err: {}", e)
                    }
                });
            }
            Ok(())
        }
        .await
    }
}
