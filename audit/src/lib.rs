#![cfg_attr(feature = "cargo-clippy", allow(module_inception))]

#[macro_use]
extern crate lazy_static;

use failure;

use netlink_proto::{sys::Protocol, Connection};

mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

use futures::sync::mpsc::UnboundedReceiver;
use netlink_packet_audit::AuditMessage;
use netlink_packet_core::NetlinkMessage;

use std::io;

pub fn new_connection() -> io::Result<(
    Connection<AuditMessage>,
    Handle,
    UnboundedReceiver<NetlinkMessage<AuditMessage>>,
)> {
    let (conn, handle, messages) = netlink_proto::new_connection(Protocol::Audit)?;
    Ok((conn, Handle::new(handle), messages))
}
