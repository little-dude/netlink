#![cfg_attr(feature = "cargo-clippy", allow(module_inception))]

extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate bytes;
extern crate eui48;
extern crate failure;
extern crate failure_derive;
extern crate futures;
extern crate tokio_core;

pub extern crate netlink_packet as packet;
pub extern crate netlink_sys;
pub use packet::constants;
extern crate netlink_proto;
pub use netlink_proto::{Connection, Protocol};

mod handle;
pub use handle::*;

mod errors;
pub use errors::*;

use futures::sync::mpsc::UnboundedReceiver;
use packet::NetlinkMessage;

// pub fn connect_multicast() -> Result<(Connection, Handle), Error> {
//     connect(Some(netlink_sys::SocketAddr::new(
//         0,
//         packet::constants::AUDIT_NLGRP_READLOG,
//     )))
// }

use std::io;

pub fn new_connection() -> io::Result<(Connection, Handle, UnboundedReceiver<NetlinkMessage>)> {
    let (conn, handle, messages) = netlink_proto::new_connection(Protocol::Audit)?;
    Ok((conn, Handle::new(handle), messages))
}
