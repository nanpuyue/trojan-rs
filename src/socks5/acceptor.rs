use super::*;

pub struct Socks5Acceptor {
    pub(super) stream: TcpStream,
    pub(super) buf: Vec<u8>,
}

impl Socks5Acceptor {
    pub async fn authenticate(&mut self) -> Result<()> {
        self.buf.resize(2, 0);
        self.stream.read_exact(&mut self.buf).await?;

        if self.buf[0] != 5 {
            return Err("Not Socks5 Request!".into());
        }

        self.buf.resize(2 + self.buf[1] as usize, 0);
        self.stream.read_exact(&mut self.buf[2..]).await?;

        if !self.buf[2..].contains(&0) {
            self.stream.write_all(b"\x05\xff").await?;
            return Err("No Supported Authentication Method!".into());
        }

        self.stream.write_all(b"\x05\x00").await?;
        Ok(())
    }

    pub async fn accept_command(&mut self) -> Result<(u8, &[u8])> {
        self.buf.resize(5, 0);
        self.stream.read_exact(&mut self.buf).await?;

        if self.buf[0] != 5 || self.buf[2] != 0 {
            return Err("Invalid Request!".into());
        }

        let len = match Socks5Target::target_len(&self.buf[3..]) {
            Ok(x) => x + 3,
            Err(e) => {
                self.stream.write_all(b"\x05\x08").await?;
                return Err(e);
            }
        };

        self.buf.resize(len, 0);
        self.stream.read_exact(&mut self.buf[5..]).await?;

        if self.buf[1] != 1 && self.buf[1] != 3 {
            self.stream.write_all(b"\x05\x07").await?;
            return Err("Unsupported Request Command!".into());
        }

        Ok((self.buf[1], &self.buf[3..]))
    }

    pub async fn connect_target<C: TargetConnector>(mut self) -> Result<()> {
        self.authenticate().await?;
        let (command, target) = self.accept_command().await?;

        if command == 3 {
            return self.associate_udp().await;
        }

        debug_assert_eq!(command, 1);
        let mut connector = C::from(command, target)?;
        eprintln!("{} -> {}", self.peer_addr(), connector.target());
        match connector.connect().await {
            Ok(_) => {
                let stream = self.connected().await?;
                let upstream = connector.connected()?;
                link_stream(stream, upstream).await?;
                Ok(())
            }
            Err(e) => {
                self.closed().await?;
                Err(e)
            }
        }
    }

    pub async fn connected(mut self) -> Result<Socks5Stream> {
        self.stream
            .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            .await?;
        Ok(self.stream)
    }

    pub async fn closed(mut self) -> Result<()> {
        self.stream
            .write_all(&[b"\x05\x01\x00", &self.buf[3..]].concat())
            .await?;
        Ok(())
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.stream.peer_addr().unwrap()
    }
}

impl From<TcpStream> for Socks5Acceptor {
    fn from(stream: TcpStream) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(64),
        }
    }
}
