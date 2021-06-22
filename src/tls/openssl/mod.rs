use std::pin::Pin;

use async_trait::async_trait;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode};
use openssl::x509::verify::X509VerifyFlags;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_openssl::SslStream;

use super::{TrojanTlsConnector, TLS_CONNECTOR};
use crate::config::CONFIG;
use crate::error::Result;
#[cfg(target_family = "unix")]
use crate::util::set_tcp_keepalive;

pub use self::connector::{set_tls_connector, TlsConnector};

mod connector;
