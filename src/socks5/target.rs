use super::*;

pub enum Socks5Target {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String),
}

impl From<Socks5Target> for DirectConnector {
    fn from(target: Socks5Target) -> Self {
        Self {
            target,
            stream: None,
        }
    }
}

impl Display for Socks5Target {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(s) => s.fmt(f),
            Self::V6(s) => s.fmt(f),
            Self::Domain(s) => s.fmt(f),
        }
    }
}

impl Socks5Target {
    pub(super) unsafe fn parse_ipv4(data: &[u8]) -> Self {
        Self::V4(SocketAddrV4::new(
            (*(data.as_ptr() as *const [u8; 4])).into(),
            u16::from_be_bytes([data[4], data[5]]),
        ))
    }

    pub(super) unsafe fn parse_ipv6(data: &[u8]) -> Self {
        Self::V6(SocketAddrV6::new(
            (*(data.as_ptr() as *const [u8; 16])).into(),
            u16::from_be_bytes([data[16], data[17]]),
            0,
            0,
        ))
    }

    pub(super) fn try_parse_domain(data: &[u8]) -> Result<Self> {
        let len = data.len();
        let domain = match String::from_utf8(data[1..len - 2].into()) {
            Ok(s) => s,
            Err(e) => return Err(format!("Invalid Domain: {}!", e).into()),
        };
        let port = u16::from_be_bytes([data[len - 2], data[len - 1]]).to_string();
        Ok(Self::Domain(domain + ":" + &port))
    }
}

pub struct DirectConnector {
    target: Socks5Target,
    stream: Option<TcpStream>,
}

#[async_trait]
pub trait TargetConnector: Send {
    type Stream: AsyncRead + AsyncWrite;

    async fn connect(&mut self) -> Result<()>;

    async fn send_request(&mut self) -> Result<()> {
        Ok(())
    }

    fn take_stream(&mut self) -> Option<Self::Stream>;
}

#[async_trait]
impl TargetConnector for DirectConnector {
    type Stream = TcpStream;

    async fn connect(&mut self) -> Result<()> {
        self.stream = Some(match &self.target {
            Socks5Target::V4(s) => TcpStream::connect(s).await?,
            Socks5Target::V6(s) => TcpStream::connect(s).await?,
            Socks5Target::Domain(s) => TcpStream::connect(s).await?,
        });

        Ok(())
    }

    fn take_stream(&mut self) -> Option<Self::Stream> {
        self.stream.take()
    }
}
