use crate::{message::RawGenlMessage, GenetlinkHandle};
use futures::channel::mpsc::UnboundedReceiver;
use netlink_packet_core::NetlinkMessage;
use netlink_proto::{
    self,
    sys::{protocols::NETLINK_GENERIC, SocketAddr},
    Connection,
};
use std::io;

/// Construct a generic netlink connection
///
/// The function would return a tuple containing three objects.
/// - an async netlink connection
/// - a connection handle to interact with the connection
/// - a receiver of the unsolicited messages
///
/// The connection object is also a event loop which implements [`std::future::Future`].
/// In most cases, users spawn it on an async runtime and use the handle to send
/// messages. For detailed documentation, please refer to [`netlink_proto::new_connection`].
///
/// The [`GenetlinkHandle`] can send and receive any type of generic netlink message.
/// And it can automatic resolve the generic family id before sending.
#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<RawGenlMessage>,
    GenetlinkHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)> {
    let (conn, handle, messages) = netlink_proto::new_connection(NETLINK_GENERIC)?;
    Ok((conn, GenetlinkHandle::new(handle), messages))
}
