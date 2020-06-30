use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    run_type: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_port: Option<u16>,
    password: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_timeout: Option<u32>,
    log_level: u8,
    ssl: SslConfig,
    tcp: TcpConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    mysql: Option<MysqlConfig>,
}

#[serde(untagged)]
#[derive(Debug, Deserialize, Serialize)]
pub enum SslConfig {
    Client {
        verify: bool,
        verify_hostname: bool,
        cert: String,
        cipher: String,
        cipher_tls13: String,
        sni: String,
        alpn: Vec<String>,
        reuse_session: bool,
        session_ticket: bool,
        curves: String,
    },
    Server {
        cert: String,
        key: String,
        key_password: String,
        cipher: String,
        cipher_tls13: String,
        prefer_server_cipher: bool,
        alpn: Vec<String>,
        alpn_port_override: HashMap<String, u16>,
        reuse_session: bool,
        session_ticket: bool,
        session_timeout: u32,
        plain_http_response: String,
        curves: String,
        dhparam: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TcpConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    prefer_ipv4: Option<bool>,
    no_delay: bool,
    keep_alive: bool,
    reuse_port: bool,
    fast_open: bool,
    fast_open_qlen: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MysqlConfig {
    enabled: bool,
    server_addr: String,
    server_port: u16,
    database: String,
    username: String,
    password: String,
    key: String,
    cert: String,
    ca: String,
}
