// SPDX-License-Identifier: MIT

mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

pub use netlink_packet_audit as packet;
pub mod proto {
    pub use netlink_proto::{Connection, ConnectionHandle, Error};
}
pub use netlink_proto::sys;

use std::io;

use futures::channel::mpsc::UnboundedReceiver;

#[allow(clippy::type_complexity)]
#[cfg(feature = "tokio_socket")]
pub fn new_connection() -> io::Result<(
    proto::Connection<packet::AuditMessage, sys::TokioSocket, packet::NetlinkAuditCodec>,
    Handle,
    UnboundedReceiver<(
        packet::NetlinkMessage<packet::AuditMessage>,
        sys::SocketAddr,
    )>,
)> {
    new_connection_with_socket()
}

#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> io::Result<(
    proto::Connection<packet::AuditMessage, S, packet::NetlinkAuditCodec>,
    Handle,
    UnboundedReceiver<(
        packet::NetlinkMessage<packet::AuditMessage>,
        sys::SocketAddr,
    )>,
)>
where
    S: sys::AsyncSocket,
{
    let (conn, handle, messages) =
        netlink_proto::new_connection_with_codec(sys::protocols::NETLINK_AUDIT)?;
    Ok((conn, Handle::new(handle), messages))
}
