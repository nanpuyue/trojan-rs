use super::*;

pub struct Socks5Listener {
    listener: TcpListener,
}

impl Socks5Listener {
    pub async fn listen<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub async fn handle_incoming(&mut self) -> Result<()> {
        async {
            let mut incoming = self.listener.incoming();
            while let Some(stream) = incoming.next().await.transpose()? {
                eprintln!("accepted connection from {}", stream.peer_addr().unwrap());
                tokio::spawn(async {
                    if let Err(e) = async {
                        let mut socks5_stream = Socks5Stream::new(stream);
                        socks5_stream.authenticate().await?;
                        socks5_stream.handle_command().await
                    }
                    .await
                    {
                        eprintln!("handle incoming err: {}", e)
                    }
                });
            }
            Ok(())
        }
        .await
    }
}
