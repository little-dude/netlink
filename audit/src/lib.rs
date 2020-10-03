mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

pub use netlink_packet_audit as packet;
pub mod proto {
    pub use netlink_proto::{Connection, ConnectionHandle, Error, ErrorKind};
}
pub use netlink_proto::sys;

use std::io;

use futures::channel::mpsc::UnboundedReceiver;

#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    proto::Connection<packet::AuditMessage>,
    Handle,
    UnboundedReceiver<(packet::NetlinkMessage<packet::AuditMessage>, sys::SocketAddr)>,
)> {
    let (conn, handle, messages) = netlink_proto::new_connection(sys::protocols::NETLINK_AUDIT)?;
    Ok((conn, Handle::new(handle), messages))
}
