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

#[derive(Debug, Deserialize, Serialize)]
pub struct SslConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_hostname: Option<bool>,
    cert: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_password: Option<String>,
    cipher: String,
    cipher_tls13: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefer_server_cipher: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    alpn: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn_port_override: Option<HashMap<String, u16>>,
    reuse_session: bool,
    session_ticket: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plain_http_response: Option<String>,
    curves: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dhparam: Option<String>,
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
