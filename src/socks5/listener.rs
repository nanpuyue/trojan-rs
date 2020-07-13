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
}

impl Stream for Socks5Listener {
    type Item = Result<(Socks5Acceptor, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (stream, client) = match self.listener.poll_accept(cx) {
            Poll::Ready(t) => t,
            Poll::Pending => return Poll::Pending,
        }?;
        Poll::Ready(Some(Ok((Socks5Acceptor::from(stream), client))))
    }
}
