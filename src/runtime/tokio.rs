use crate::{AsyncUdpSocket, Error, IntermediateSocket};

use async_trait::async_trait;
use futures_core::{Future, Stream};
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

pub use tokio::net::UdpSocket;
pub use tokio::spawn;
pub fn create_interval_stream(request_interval: Duration) -> impl Stream<Item = Instant> {
    tokio_stream::wrappers::IntervalStream::new(tokio::time::interval_at(
        tokio::time::Instant::now() + request_interval,
        request_interval,
    ))
}

pub fn make_async_socket(
    socket: impl Into<IntermediateSocket>,
) -> Result<impl AsyncUdpSocket, Error> {
    let intermediate: IntermediateSocket = socket.into();
    Ok(TryInto::<Arc<tokio::net::UdpSocket>>::try_into(
        intermediate,
    )?)
}

pub async fn timeout<F, T>(timeout: Duration, future: F) -> Result<T, crate::errors::TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future).await
}

#[async_trait]
impl AsyncUdpSocket for Arc<tokio::net::UdpSocket> {
    async fn send_to(
        &self,
        buf: &[u8],
        target: impl Into<SocketAddr> + Send,
    ) -> std::io::Result<usize> {
        tokio::net::UdpSocket::send_to(&self, buf, target.into()).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(&self, buf).await
    }
}

impl TryFrom<crate::IntermediateSocket> for Arc<tokio::net::UdpSocket> {
    type Error = crate::errors::Error;

    fn try_from(socket: IntermediateSocket) -> Result<Self, Self::Error> {
        Ok(Arc::new(UdpSocket::from_std(socket.0)?))
    }
}
