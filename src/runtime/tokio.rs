use crate::{AsyncUdpSocket, Error, IntermediateSocket};

use async_trait::async_trait;
use futures_core::{Future, Stream};
use std::io;
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

#[cfg(feature = "multihome")]
pub fn make_multihome_async_socket(
    socket: multicast_socket::MulticastSocket,
) -> Result<impl AsyncUdpSocket, Error> {
    let intermediate: IntermediateSocket = socket.into();
    Ok(TryInto::<Arc<multicast_socket::AsyncMulticastSocket>>::try_into(intermediate)?)
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
        if let crate::IntermediateSocketType::StdNetSocket(sock) = socket.take_inner() {
            Ok(Arc::new(UdpSocket::from_std(sock)?))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Couldn't create AsyncUdpSocket, expected a std::net::UdpSocket",
            )
            .into())
        }
    }
}

impl TryFrom<crate::IntermediateSocket> for Arc<multicast_socket::AsyncMulticastSocket> {
    type Error = crate::errors::Error;

    fn try_from(socket: IntermediateSocket) -> Result<Self, Self::Error> {
        if let crate::IntermediateSocketType::MultihomeSocket(sock) = socket.take_inner() {
            Ok(Arc::new(multicast_socket::AsyncMulticastSocket::try_from(
                sock,
            )?))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Couldn't create AsyncUdpSocket, expected a multicast_socket::MulticastSocket",
            )
            .into())
        }
    }
}

#[async_trait]
impl AsyncUdpSocket for Arc<multicast_socket::AsyncMulticastSocket> {
    async fn send_to(
        &self,
        buf: &[u8],
        target: impl Into<SocketAddr> + Send,
    ) -> std::io::Result<usize> {
        if let SocketAddr::V4(addr) = target.into() {
            multicast_socket::AsyncMulticastSocket::broadcast_to(&self, buf, addr).await?;
            Ok(buf.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Sending to the ipv6 multicast address on multihome UDP sockets is not currently supported",
            ))
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let msg = multicast_socket::AsyncMulticastSocket::receive(&self).await?;
        let (data, origin_addr) = (msg.data, msg.origin_address);
        if data.len() > buf.len() {
            Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Receive buffer smaller than received payload",
            ))
        } else {
            let payload_size = data.len();
            for (dst_byte, src_byte) in buf.iter_mut().zip(&data) {
                *dst_byte = *src_byte
            }
            Ok((payload_size, origin_addr.into()))
        }
    }
}
