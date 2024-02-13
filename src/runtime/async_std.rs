use crate::{AsyncUdpSocket, Error, IntermediateSocket};

use async_std::future::TimeoutError;
use async_trait::async_trait;
use futures_core::{Future, Stream};
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};

pub use async_std::net::UdpSocket;
pub use async_std::task::spawn;

pub fn create_interval_stream(request_interval: Duration) -> impl Stream<Item = ()> {
    async_std::stream::interval(request_interval)
}

pub fn make_async_socket(
    socket: impl Into<IntermediateSocket>,
) -> Result<impl AsyncUdpSocket, Error> {
    let intermediate: IntermediateSocket = socket.into();
    Ok(TryInto::<Arc<async_std::net::UdpSocket>>::try_into(
        intermediate,
    )?)
}

pub async fn timeout<F, T>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    async_std::future::timeout(timeout, future).await
}

#[async_trait]
impl AsyncUdpSocket for Arc<async_std::net::UdpSocket> {
    async fn send_to(
        &self,
        buf: &[u8],
        target: impl Into<SocketAddr> + Send,
    ) -> std::io::Result<usize> {
        async_std::net::UdpSocket::send_to(&self, buf, target.into()).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        async_std::net::UdpSocket::recv_from(&self, buf).await
    }
}

impl TryFrom<crate::IntermediateSocket> for Arc<async_std::net::UdpSocket> {
    type Error = crate::errors::Error;

    fn try_from(socket: IntermediateSocket) -> Result<Self, Self::Error> {
        Ok(Arc::new(UdpSocket::from(socket.0)))
    }
}
