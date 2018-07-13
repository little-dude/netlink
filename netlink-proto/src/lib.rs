#![cfg(any(feature = "rtnetlink"))]

extern crate bytes;
extern crate core;
extern crate failure;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate tokio_io;

#[cfg(any(feature = "rtnetlink"))]
extern crate netlink_packet;
#[cfg(any(feature = "rtnetlink"))]
extern crate netlink_sys;

mod codecs;
pub use codecs::*;

mod framed;
pub use framed::*;

mod connection;
pub use connection::*;

mod errors;
pub use errors::*;

mod handle;
pub use handle::*;

mod request;
pub(crate) use request::Request;

use netlink_packet::NetlinkMessage;
pub use netlink_sys::{Protocol, SocketAddr};

use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use std::io;

pub fn new_connection(
    protocol: Protocol,
) -> io::Result<(
    Connection,
    ConnectionHandle,
    UnboundedReceiver<NetlinkMessage>,
)> {
    let (requests_tx, requests_rx) = unbounded::<Request>();
    let (messages_tx, messages_rx) = unbounded::<NetlinkMessage>();
    Ok((
        Connection::new(requests_rx, messages_tx, protocol)?,
        ConnectionHandle::new(requests_tx),
        messages_rx,
    ))
}
