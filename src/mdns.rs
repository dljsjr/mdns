use crate::AsyncUdpSocket;
use crate::{Error, Response};

use std::{io, net::Ipv4Addr};

use async_stream::try_stream;
use futures_core::Stream;

use std::net::SocketAddr;

/// The IP address for the mDNS multicast socket.
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;

const DEFAULT_BUFFER_SIZE: usize = 4096;

pub fn mdns_interface(
    service_name: String,
    interface_addr: Ipv4Addr,
) -> Result<
    (
        mDNSListener<impl AsyncUdpSocket>,
        mDNSSender<impl AsyncUdpSocket>,
    ),
    Error,
> {
    let socket = create_socket()?;

    socket.set_multicast_loop_v4(false)?;
    socket.set_nonblocking(true)?; // explicitly set nonblocking for wider compatability
    socket.join_multicast_v4(&MULTICAST_ADDR, &interface_addr)?;

    let socket = crate::runtime::make_async_socket(socket)?;

    let recv_buffer = vec![0; DEFAULT_BUFFER_SIZE];

    Ok((
        mDNSListener {
            recv: socket.clone(),
            recv_buffer,
        },
        mDNSSender {
            service_name,
            send: socket,
        },
    ))
}

#[cfg(feature = "multihome")]
pub fn multihome_mdns_interface(
    service_name: String,
) -> Result<
    (
        mDNSListener<impl AsyncUdpSocket>,
        mDNSSender<impl AsyncUdpSocket>,
    ),
    Error,
> {
    use multicast_socket::MulticastSocket;

    let socket = MulticastSocket::with_options(
        std::net::SocketAddrV4::new(MULTICAST_ADDR, MULTICAST_PORT),
        multicast_socket::all_ipv4_interfaces()?,
        multicast_socket::MulticastOptions {
            read_timeout: None,
            loopback: false,
            buffer_size: DEFAULT_BUFFER_SIZE,
            bind_address: Ipv4Addr::UNSPECIFIED,
            nonblocking: true,
        },
    )?;

    let socket = crate::runtime::make_multihome_async_socket(socket)?;
    let recv_buffer = vec![0; DEFAULT_BUFFER_SIZE];

    Ok((
        mDNSListener {
            recv: socket.clone(),
            recv_buffer,
        },
        mDNSSender {
            service_name,
            send: socket,
        },
    ))
}

const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

#[cfg(not(target_os = "windows"))]
fn create_socket() -> io::Result<std::net::UdpSocket> {
    let socket_addr = std::net::SocketAddrV4::new(ADDR_ANY, MULTICAST_PORT);
    let domain = socket2::Domain::for_address(SocketAddr::V4(socket_addr));
    let ty = socket2::Type::DGRAM;
    let socket = socket2::Socket::new(domain, ty, Some(socket2::Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::V4(socket_addr).into())?;

    Ok(socket.into())
}

#[cfg(target_os = "windows")]
fn create_socket() -> io::Result<std::net::UdpSocket> {
    let socket_addr = std::net::SocketAddrV4::new(ADDR_ANY, MULTICAST_PORT);
    let domain = socket2::Domain::for_address(SocketAddr::V4(socket_addr));
    let ty = socket2::Type::DGRAM;
    let socket = socket2::Socket::new(domain, ty, Some(socket2::Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::V4(socket_addr).into())?;

    Ok(socket.into())
}

/// An mDNS sender on a specific interface.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct mDNSSender<T: AsyncUdpSocket> {
    service_name: String,
    send: T,
}

impl<T: AsyncUdpSocket> mDNSSender<T> {
    /// Send multicasted DNS queries.
    pub async fn send_request(&mut self) -> Result<(), Error> {
        let mut builder = dns_parser::Builder::new_query(0, false);
        let prefer_unicast = false;
        builder.add_question(
            &self.service_name,
            prefer_unicast,
            dns_parser::QueryType::PTR,
            dns_parser::QueryClass::IN,
        );
        // This builder users the Error position to return a *valid* truncated packet 🤦
        let packet_data = builder.build().unwrap_or_else(|x| x);

        let addr = SocketAddr::new(MULTICAST_ADDR.into(), MULTICAST_PORT);

        self.send.send_to(&packet_data, addr).await?;
        Ok(())
    }
}

/// An mDNS listener on a specific interface.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct mDNSListener<T: AsyncUdpSocket> {
    pub(crate) recv: T,
    pub(crate) recv_buffer: Vec<u8>,
}

impl<T: AsyncUdpSocket> mDNSListener<T> {
    pub fn listen(mut self) -> impl Stream<Item = Result<Response, Error>> {
        try_stream! {
            loop {
                let (count, _) = self.recv.recv_from(&mut self.recv_buffer).await?;
                if count > 0 {
                    match dns_parser::Packet::parse(&self.recv_buffer[..count]) {
                        Ok(raw_packet) => yield Response::from_packet(&raw_packet),
                        Err(e) => log::warn!("{}, {:?}", e, &self.recv_buffer[..count]),
                    }
                }
            }
        }
    }
}
