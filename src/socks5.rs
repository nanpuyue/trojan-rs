use std::fmt::{Display, Formatter};
use std::net::{SocketAddrV4, SocketAddrV6};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::stream::StreamExt;

use crate::error::Result;
use crate::trojan::TrojanConnector;
use crate::util::link_stream;

pub use self::{
    listener::Socks5Listener,
    stream::Socks5Stream,
    target::{DirectConnector, Socks5Target, TargetConnector},
};

mod listener;
mod stream;
mod target;
