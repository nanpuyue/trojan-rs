use std::fmt::{Display, Formatter};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::stream::Stream;

use crate::error::Result;
use crate::util::link_stream;

pub use self::{
    acceptor::Socks5Acceptor,
    listener::Socks5Listener,
    target::{DirectConnector, Socks5Target, TargetConnector},
};

pub type Socks5Stream = TcpStream;

mod acceptor;
mod listener;
mod target;
