use super::*;

pub struct Socks5UdpClient {
    udp_socket: UdpSocket,
    client_addr: SocketAddr,
}

impl Socks5UdpClient {
    pub fn new(udp_socket: UdpSocket, client_addr: SocketAddr) -> Self {
        Self {
            udp_socket,
            client_addr,
        }
    }

    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    pub async fn connect(self) -> Result<UdpSocket> {
        self.udp_socket.connect(self.client_addr).await?;
        Ok(self.udp_socket)
    }
}

impl Socks5Acceptor {
    pub async fn associate_udp<C: TargetConnector>(mut self) -> Result<()> {
        let mut local = self.stream.local_addr()?;
        local.set_port(0);
        let udp_socket = UdpSocket::bind(&local).await?;

        let mut client_addr = self.stream.peer_addr()?;
        let target = &self.buf[3..];
        let client_port = u16::from_be_bytes([target[target.len() - 2], target[target.len() - 1]]);
        client_addr.set_port(client_port);

        eprintln!("{} == {} (udp)", client_addr, udp_socket.local_addr()?);
        let reply = match udp_socket.local_addr()? {
            SocketAddr::V4(x) => [
                b"\x05\x00\x00\x01".as_ref(),
                x.ip().octets().as_ref(),
                x.port().to_be_bytes().as_ref(),
            ]
            .concat(),
            SocketAddr::V6(x) => [
                b"\x05\x00\x00\x04".as_ref(),
                x.ip().octets().as_ref(),
                x.port().to_be_bytes().as_ref(),
            ]
            .concat(),
        };
        self.stream.write_all(&reply).await?;

        let mut connector = C::from(3, target)?;
        if let Err(e) = connector.udp_bind().await {
            self.closed(1).await?;
            return Err(e);
        };

        let done = async {
            self.stream.read(&mut [0]).await?;
            Ok(())
        };

        let udp_client = Socks5UdpClient::new(udp_socket, client_addr);
        let forward_udp = connector.forward_udp(udp_client);

        tokio::select! {
            r1 = done => {
                r1
            },
            r2 = forward_udp => {
                r2
            },
        }
    }
}
