use super::*;

pub struct Socks5Acceptor {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Socks5Acceptor {
    pub async fn authenticate(&mut self) -> Result<()> {
        let mut n;
        let mut len = 0;

        self.buf.clear();
        while {
            n = self.stream.read_buf(&mut self.buf).await?;
            n > 0
        } {
            if self.buf.len() >= 2 {
                len = 2 + self.buf[1] as usize;
            }

            if len > 0 && self.buf.len() >= len {
                break;
            }
        }
        if len == 0 || self.buf.len() != len || self.buf[0] != 5 {
            return Err("Invalid Request!".into());
        }

        if !self.buf[2..].contains(&0) {
            self.stream.write_all(b"\x05\xff").await?;
            return Err("No Supported Authentication Method!".into());
        }

        self.stream.write_all(b"\x05\x00").await?;
        Ok(())
    }

    pub async fn accept_command(&mut self) -> Result<(u8, &[u8])> {
        let mut n;
        let mut len = 0;

        self.buf.clear();
        while {
            n = self.stream.read_buf(&mut self.buf).await?;
            n > 0
        } {
            if len == 0 && self.buf.len() >= 5 {
                len = match self.buf[3] {
                    1 => 10,
                    4 => 22,
                    3 => 7 + self.buf[4] as usize,
                    _ => {
                        self.stream.write_all(b"\x05\x08").await?;
                        return Err("Invalid Address Type!".into());
                    }
                };
            }

            if len > 0 && self.buf.len() >= len {
                break;
            }
        }

        if len == 0 || self.buf.len() != len || self.buf[0] != 5 || self.buf[2] != 0 {
            return Err("Invalid Request!".into());
        }

        if self.buf[1] != 1 {
            self.stream.write_all(b"\x05\x07").await?;
            return Err("Unsupported Request Command!".into());
        }

        Ok((self.buf[1], &self.buf[3..]))
    }

    pub async fn connect_target<C: TargetConnector>(mut self) -> Result<()> {
        self.authenticate().await?;
        let (command, target) = self.accept_command().await?;
        debug_assert_eq!(command, 1);

        let mut connector = C::from(target)?;
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
            buf: Vec::with_capacity(512),
        }
    }
}
