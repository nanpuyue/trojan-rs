use async_trait::async_trait;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_openssl::{connect, SslStream};

use self::verify::*;
use super::TLS_CONNECTOR;
use crate::config::CONFIG;
use crate::error::Result;

#[allow(dead_code)]
#[allow(clippy::transmute_ptr_to_ptr)]
mod verify;

pub struct TlsConnector {
    connector: SslConnector,
    sni: bool,
    verify_hostname: bool,
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn set_tls_connector() -> Result<()> {
    let ssl_config = CONFIG.get_ref().ssl.client()?;

    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    if !ssl_config.verify {
        builder.set_verify(SslVerifyMode::NONE);
    };

    if !ssl_config.cert.is_empty() {
        builder.set_ca_file(&ssl_config.cert)?;
    }

    if !ssl_config.cipher.is_empty() {
        builder.set_cipher_list(&ssl_config.cipher)?;
    }

    if !ssl_config.cipher_tls13.is_empty() {
        builder.set_ciphersuites(&ssl_config.cipher_tls13)?;
    }

    if !ssl_config.alpn.is_empty() {
        let mut alpn_protos = Vec::new();
        for alpn in &ssl_config.alpn {
            if !alpn.is_empty() {
                alpn_protos.push(alpn.len() as u8);
                alpn_protos.extend_from_slice(alpn.as_bytes());
            }
        }

        if !alpn_protos.is_empty() {
            builder.set_alpn_protos(&alpn_protos)?;
        }
    }

    if !ssl_config.reuse_session {
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    }

    if !ssl_config.session_ticket {
        builder.set_options(SslOptions::NO_TICKET);
    }

    // TODO: set curves list

    TLS_CONNECTOR.write(TlsConnector {
        connector: builder.build(),
        sni: !ssl_config.sni.is_empty(),
        verify_hostname: ssl_config.verify_hostname,
    });

    Ok(())
}

#[async_trait]
impl super::TrojanTlsConnector for TlsConnector {
    type Stream = SslStream<TcpStream>;

    async fn connect<A>(&self, addr: A, domain: &str) -> Result<Self::Stream>
    where
        A: ToSocketAddrs + Send + Sync,
    {
        let mut config = self.connector.configure()?;
        let pub_config = config.trans_public();
        pub_config
            .ssl
            .param_mut()
            .set_flags(X509_V_FLAG_PARTIAL_CHAIN);
        pub_config.sni = self.sni;
        pub_config.verify_hostname = self.verify_hostname;

        let tcpstream = TcpStream::connect(addr).await?;
        let stream = connect(config, domain, tcpstream).await?;

        Ok(stream)
    }
}
