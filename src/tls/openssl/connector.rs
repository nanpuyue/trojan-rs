use super::*;

pub struct TlsConnector {
    connector: SslConnector,
    sni: bool,
    verify_hostname: bool,
    tcp_nodelay: bool,
    #[allow(dead_code)]
    tcp_keepalive: bool,
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn set_tls_connector() -> Result<()> {
    let ssl_config = CONFIG.assume_init_ref().ssl.client()?;

    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    // builder.set_keylog_callback(|_, keylog| println!("{}", keylog));

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

    let tcp_config = &CONFIG.assume_init_ref().tcp;
    TLS_CONNECTOR.write(TlsConnector {
        connector: builder.build(),
        sni: !ssl_config.sni.is_empty(),
        verify_hostname: ssl_config.verify_hostname,
        tcp_nodelay: tcp_config.no_delay,
        tcp_keepalive: tcp_config.keep_alive,
    });

    Ok(())
}

#[async_trait]
impl TrojanTlsConnector for TlsConnector {
    type Stream = SslStream<TcpStream>;

    async fn connect<A>(&self, addr: A, domain: &str) -> Result<Self::Stream>
    where
        A: ToSocketAddrs + Send + Sync,
    {
        let mut config = self.connector.configure()?;
        config.set_use_server_name_indication(self.sni);
        config.set_verify_hostname(self.verify_hostname);
        let mut ssl = config.into_ssl(domain)?;
        ssl.param_mut().set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;

        let tcpstream = TcpStream::connect(addr).await?;
        tcpstream.set_nodelay(self.tcp_nodelay)?;
        #[cfg(target_family = "unix")]
        set_tcp_keepalive(&tcpstream, self.tcp_keepalive)?;

        let mut stream = SslStream::new(ssl, tcpstream)?;
        Pin::new(&mut stream).connect().await?;

        Ok(stream)
    }
}
