#![cfg_attr(feature = "cargo-clippy", allow(module_inception))]


#[macro_use]
extern crate lazy_static;


use failure;




pub use netlink_packet as packet;
pub use netlink_sys;
pub use crate::packet::constants;
use netlink_proto;
pub use netlink_proto::{Connection, Protocol};

mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

use futures::sync::mpsc::UnboundedReceiver;
use crate::packet::NetlinkMessage;

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
