use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;

pub use self::ssl::Config as SslConfig;

pub static mut CONFIG: MaybeUninit<Config> = MaybeUninit::uninit();

#[allow(clippy::missing_safety_doc)]
pub unsafe fn set_config<P: AsRef<Path>>(path: P) -> Result<()> {
    let mut file = File::open(path)?;
    let json = &mut String::new();
    file.read_to_string(json)?;

    let config = serde_json::from_str::<Config>(json)?;
    CONFIG.write(config);

    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub run_type: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    pub password: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<u32>,
    pub log_level: u8,
    pub ssl: SslConfig,
    pub tcp: TcpConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mysql: Option<MysqlConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TcpConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_ipv4: Option<bool>,
    pub no_delay: bool,
    pub keep_alive: bool,
    pub reuse_port: bool,
    pub fast_open: bool,
    pub fast_open_qlen: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MysqlConfig {
    pub enabled: bool,
    pub server_addr: String,
    pub server_port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub key: String,
    pub cert: String,
    pub ca: String,
}

mod ssl {
    use super::*;

    use std::collections::HashMap;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Client {
        pub verify: bool,
        pub verify_hostname: bool,
        pub cert: String,
        pub cipher: String,
        pub cipher_tls13: String,
        pub sni: String,
        pub alpn: Vec<String>,
        pub reuse_session: bool,
        pub session_ticket: bool,
        pub curves: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Server {
        pub cert: String,
        pub key: String,
        pub key_password: String,
        pub cipher: String,
        pub cipher_tls13: String,
        pub prefer_server_cipher: bool,
        pub alpn: Vec<String>,
        pub alpn_port_override: HashMap<String, u16>,
        pub reuse_session: bool,
        pub session_ticket: bool,
        pub session_timeout: u32,
        pub plain_http_response: String,
        pub curves: String,
        pub dhparam: String,
    }

    #[serde(untagged)]
    #[derive(Debug, Deserialize, Serialize)]
    pub enum Config {
        Client(Client),
        Server(Server),
    }

    impl Config {
        pub fn client(&self) -> Result<&Client> {
            match self {
                Self::Client(c) => Ok(c),
                _ => Err("Not a client configuration!".into()),
            }
        }

        pub fn server(&self) -> Result<&Server> {
            match self {
                Self::Server(s) => Ok(s),
                _ => Err("Not a server configuration!".into()),
            }
        }
    }
}
