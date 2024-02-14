//! Utilities for discovering devices on the LAN.
//!
//! Examples
//!
//! ```rust,no_run
//! use futures_util::{pin_mut, stream::StreamExt};
//! use mdns::{Error, Record, RecordKind};
//! use std::time::Duration;
//!
//! const SERVICE_NAME: &'static str = "_googlecast._tcp.local";
//!
//! #[cfg_attr(feature = "runtime-async-std", async_std::main)]
//! #[cfg_attr(feature = "runtime-tokio", tokio::main)]
//! async fn main() -> Result<(), Error> {
//!     let stream = mdns::discover::all(SERVICE_NAME, Duration::from_secs(15))?.listen();
//!     pin_mut!(stream);
//!
//!     while let Some(Ok(response)) = stream.next().await {
//!         println!("{:?}", response);
//!     }
//!
//!     Ok(())
//! }
//! ```

use crate::{mDNSListener, AsyncUdpSocket, Error, Response};

use std::time::Duration;

use crate::mdns::{mDNSSender, mdns_interface};
use futures_core::Stream;
use futures_util::{future::ready, stream::select, StreamExt};
use std::net::Ipv4Addr;

/// A multicast DNS discovery request.
///
/// This represents a single lookup of a single service name.
///
/// This object can be iterated over to yield the received mDNS responses.
pub struct Discovery<T: AsyncUdpSocket, U: AsyncUdpSocket> {
    service_name: String,

    mdns_sender: mDNSSender<T>,
    mdns_listener: mDNSListener<U>,

    /// Whether we should ignore empty responses.
    ignore_empty: bool,

    /// The interval we should send mDNS queries.
    send_request_interval: Duration,
}

/// Gets an iterator over all responses for a given service on all interfaces.
#[cfg(feature = "multihome")]
pub fn all<S>(
    service_name: S,
    mdns_query_interval: Duration,
) -> Result<Discovery<impl AsyncUdpSocket + 'static, impl AsyncUdpSocket + 'static>, Error>
where
    S: AsRef<str>,
{
    use crate::mdns::multihome_mdns_interface;

    let service_name = service_name.as_ref().to_string();
    let (mdns_listener, mdns_sender) = multihome_mdns_interface(service_name.clone())?;

    Ok(Discovery {
        service_name,
        mdns_sender,
        mdns_listener,
        ignore_empty: true,
        send_request_interval: mdns_query_interval,
    })
}

/// Gets an iterator over all responses for a given service on a given interface.
pub fn interface<S>(
    service_name: S,
    mdns_query_interval: Duration,
    interface_addr: Ipv4Addr,
) -> Result<Discovery<impl AsyncUdpSocket + 'static, impl AsyncUdpSocket + 'static>, Error>
where
    S: AsRef<str>,
{
    let service_name = service_name.as_ref().to_string();
    let (mdns_listener, mdns_sender) = mdns_interface(service_name.clone(), interface_addr)?;

    Ok(Discovery {
        service_name,
        mdns_sender,
        mdns_listener,
        ignore_empty: true,
        send_request_interval: mdns_query_interval,
    })
}

impl<T: AsyncUdpSocket + Send + 'static, U: AsyncUdpSocket + Send + 'static> Discovery<T, U> {
    /// Sets whether or not we should ignore empty responses.
    ///
    /// Defaults to `true`.
    pub fn ignore_empty(mut self, ignore: bool) -> Self {
        self.ignore_empty = ignore;
        self
    }

    pub fn listen(self) -> impl Stream<Item = Result<Response, Error>> {
        let ignore_empty = self.ignore_empty;
        let service_name = self.service_name;
        let response_stream = self.mdns_listener.listen();
        let sender = self.mdns_sender.clone();

        let response_stream = response_stream.map(StreamResult::Response);
        let interval_stream = crate::runtime::create_interval_stream(self.send_request_interval)
            .map(move |_| {
                let mut sender = sender.clone();
                crate::runtime::spawn(async move {
                    if let Err(e) = sender.send_request().await {
                        log::error!("Error sending query from interval stream: {e:?}");
                    }
                });
                StreamResult::Interval
            });

        let sender = self.mdns_sender.clone();
        crate::runtime::spawn(async {
            let mut sender = sender;
            if let Err(e) = sender.send_request().await {
                log::error!("Error sending query from initial query: {e:?}");
            }
        });
        let stream = select(response_stream, interval_stream);
        stream
            .filter_map(|stream_result| async {
                match stream_result {
                    StreamResult::Interval => None,
                    StreamResult::Response(res) => Some(res),
                }
            })
            .filter(move |res| {
                ready(match res {
                    Ok(response) => {
                        (!response.is_empty() || !ignore_empty)
                            && response
                                .answers
                                .iter()
                                .any(|record| record.name == service_name)
                    }
                    Err(e) => {
                        log::warn!("Error on listener stream: {e:?}");
                        true
                    }
                })
            })
    }
}

pub enum StreamResult {
    Interval,
    Response(Result<crate::Response, crate::Error>),
}
