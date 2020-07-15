use std::mem::MaybeUninit;

use async_trait::async_trait;
use tokio::net::ToSocketAddrs;

use crate::error::Result;

pub use self::openssl::{set_tls_connector, TlsConnector};

mod openssl;

pub static mut TLS_CONNECTOR: MaybeUninit<TlsConnector> = MaybeUninit::uninit();

#[async_trait]
pub trait TrojanTlsConnector {
    type Stream: Send;

    async fn connect<A>(&self, addr: A, domain: &str) -> Result<Self::Stream>
    where
        A: ToSocketAddrs + Send + Sync;
}
