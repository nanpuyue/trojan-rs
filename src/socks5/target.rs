use super::*;

pub enum Socks5Target {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String),
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
    fn parse_ipv4(data: &[u8]) -> Self {
        debug_assert_eq!(data.len(), 6);
        Self::V4(SocketAddrV4::new(
            (unsafe { *(data.as_ptr() as *const [u8; 4]) }).into(),
            u16::from_be_bytes([data[4], data[5]]),
        ))
    }

    fn parse_ipv6(data: &[u8]) -> Self {
        debug_assert_eq!(data.len(), 18);
        Self::V6(SocketAddrV6::new(
            (unsafe { *(data.as_ptr() as *const [u8; 16]) }).into(),
            u16::from_be_bytes([data[16], data[17]]),
            0,
            0,
        ))
    }

    fn parse_domain(data: &[u8]) -> Result<Self> {
        let len = data.len();
        debug_assert_eq!(len, 3 + data[0] as usize);
        let domain = match String::from_utf8(data[1..len - 2].into()) {
            Ok(s) => s,
            Err(e) => return Err(format!("Invalid Domain: {}!", e).into()),
        };
        let port = u16::from_be_bytes([data[len - 2], data[len - 1]]).to_string();
        Ok(Self::Domain(domain + ":" + &port))
    }

    pub fn target_len(data: &[u8]) -> Result<usize> {
        debug_assert!(data.len() >= 2);
        Ok(match data[0] {
            1 => 7,
            4 => 19,
            3 => 4 + data[1] as usize,
            _ => return Err("Invalid Address Type!".into()),
        })
    }

    pub fn try_parse(data: &[u8]) -> Result<Socks5Target> {
        Ok(match data[0] {
            1 => Self::parse_ipv4(&data[1..]),
            4 => Self::parse_ipv6(&data[1..]),
            3 => Self::parse_domain(&data[1..])?,
            _ => return Err("Invalid Address Type!".into()),
        })
    }
}

#[async_trait]
pub trait TargetConnector: Send {
    type Stream: AsyncRead + AsyncWrite;

    async fn connect(&mut self) -> Result<()>;

    fn connected(self) -> Result<Self::Stream>;

    async fn forward_udp(client: Socks5UdpClient, upstream: Self::Stream) -> Result<()>;

    fn from(command: u8, target: &[u8]) -> Result<Self>
    where
        Self: Sized;

    fn target(&self) -> &Socks5Target;
}

pub struct DirectConnector {
    target: Socks5Target,
    stream: Option<TcpStream>,
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

    fn connected(mut self) -> Result<Self::Stream> {
        Ok(self.stream.take()?)
    }

    async fn forward_udp(client: Socks5UdpClient, upstream: Self::Stream) -> Result<()> {
        unimplemented!()
    }

    fn from(_: u8, target: &[u8]) -> Result<Self> {
        Ok(Self {
            target: Socks5Target::try_parse(target)?,
            stream: None,
        })
    }

    fn target(&self) -> &Socks5Target {
        &self.target
    }
}
