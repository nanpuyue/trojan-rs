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

    pub async fn connect_target<C: TargetConnector>(self) -> Result<()> {
        let mut connector = C::from(1, &self.buf[3..])?;
        let mut stream = self.connected().await?;
        connector.connect().await?;

        let buf = &mut Vec::new();
        stream.read_buf(buf).await?;
        let upstream = connector.connected(buf).await?;
        link_stream(stream, upstream).await?;

        Ok(())
    }

    pub async fn accept(mut self, router: Option<&Router>) -> Result<()> {
        self.authenticate().await?;
        let (command, target) = self.accept_command().await?;
        let target = Socks5Target::try_parse(target)?;

        if command == 3 {
            // TODO: udp associate route
            return match router.map_or(Action::Proxy, |x| x.default()) {
                Action::Proxy => self.associate_udp::<TrojanConnector<(&str, u16)>>().await,
                Action::Direct => self.associate_udp::<DirectConnector>().await,
                _ => unreachable!(),
            };
        }

        let action = match router {
            Some(x) => x.route(&target),
            None => Action::Proxy,
        };

        match action {
            Action::Direct => {
                eprintln!("{} -> {}", self.peer_addr(), target);
                self.connect_target::<DirectConnector>().await
            }
            Action::Proxy => {
                eprintln!("{} ~> {}", self.peer_addr(), target);
                self.connect_target::<TrojanConnector<(&str, u16)>>().await
            }
            Action::Reject => {
                eprintln!("{} -! {}", self.peer_addr(), target);
                self.closed(2).await
            }
        }
    }

    pub async fn connected(mut self) -> Result<Socks5Stream> {
        self.stream
            .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            .await?;
        Ok(self.stream)
    }

    pub async fn closed(mut self, resp: u8) -> Result<()> {
        // resp:
        //   0x00 succeeded
        //   0x01 general SOCKS server failure
        //   0x02 connection not allowed by ruleset
        //   0x03 Network unreachable
        //   0x04 Host unreachable
        //   0x05 Connection refused
        //   0x06 TTL expired
        //   0x07 Command not supported
        //   0x08 Address type not supported
        //   0x09 to 0xff unassigned
        self.stream
            .write_all(&[&[0x05, 0x01, resp], &self.buf[3..]].concat())
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
