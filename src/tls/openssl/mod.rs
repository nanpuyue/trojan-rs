use std::mem::transmute;
use std::time::Duration;

use async_trait::async_trait;
use libc::{c_char, c_ulong, time_t};
use openssl::ssl::{
    ConnectConfiguration, Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode,
    SslVerifyMode,
};
use openssl::x509::verify::X509VerifyParamRef;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_openssl::{connect, SslStream};

use super::{TrojanTlsConnector, TLS_CONNECTOR};
use crate::config::CONFIG;
use crate::error::Result;

pub use self::{
    connector::{set_tls_connector, TlsConnector},
    verify::{flag::*, SetFlags, TransPublic},
};

mod connector;
#[allow(dead_code, clippy::transmute_ptr_to_ptr)]
mod verify;
