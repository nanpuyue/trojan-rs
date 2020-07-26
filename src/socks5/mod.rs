use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use tokio::stream::Stream;

use crate::error::Result;
use crate::route::{Action, Router};
use crate::trojan::TrojanConnector;
use crate::util::link_stream;

pub use self::{
    acceptor::Socks5Acceptor,
    listener::Socks5Listener,
    target::{DirectConnector, Socks5Target, TargetConnector},
    udp::Socks5UdpClient,
};

pub type Socks5Stream = TcpStream;

mod acceptor;
mod listener;
mod target;
mod udp;
