use super::*;

pub struct Socks5Stream {
    stream: TcpStream,
    buf: Vec<u8>,
    target: Vec<u8>,
}

impl Socks5Stream {
    pub(super) fn new(stream: TcpStream) -> Self {
        Socks5Stream {
            stream,
            buf: Vec::with_capacity(512),
            target: Vec::new(),
        }
    }

    pub(super) async fn authenticate(&mut self) -> Result<()> {
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

    pub(super) unsafe fn parse_target(&self) -> Result<Socks5Target> {
        Ok(match self.target[0] {
            1 => Socks5Target::parse_ipv4(&self.target[1..]),
            4 => Socks5Target::parse_ipv6(&self.target[1..]),
            3 => Socks5Target::try_parse_domain(&self.target[1..])?,
            _ => unreachable!(),
        })
    }

    pub(super) async fn handle_command(mut self) -> Result<()> {
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

        self.target = self.buf.split_off(3);

        self.handle_connect::<DirectConnector>().await
    }

    pub(super) async fn handle_connect<C: TargetConnector + From<Socks5Target>>(
        mut self,
    ) -> Result<()> {
        let target = unsafe { self.parse_target()? };
        eprintln!("connect {}...", target);

        let connector = &mut C::from(target);
        match connector.connect().await {
            Ok(_) => {
                self.stream
                    .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    .await?;
                connector.send_request().await?;
                link_stream(self.stream, connector.take_stream().unwrap()).await
            }
            Err(e) => {
                self.stream
                    .write_all(&[b"\x05\x01\x00", &self.buf[3..]].concat())
                    .await?;
                Err(e)
            }
        }
    }
}
