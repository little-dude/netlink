#![cfg(any(feature = "audit", feature = "rtnetlink"))]

#[macro_use]
extern crate futures;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

mod codecs;
pub use crate::codecs::*;

mod framed;
pub use crate::framed::*;

mod connection;
pub use crate::connection::*;

mod errors;
pub use crate::errors::*;

mod handle;
pub use crate::handle::*;

mod request;
pub(crate) use crate::request::Request;

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
