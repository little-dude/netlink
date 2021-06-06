use std::io;

use futures::channel::mpsc::UnboundedReceiver;
use netlink_packet_core::NetlinkMessage;
use netlink_proto::{self, Connection};
use netlink_sys::{constants::NETLINK_GENERIC, SocketAddr};

use crate::{GenericNetlinkHandle, GenericNetlinkMessage};

#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<GenericNetlinkMessage>,
    GenericNetlinkHandle,
    UnboundedReceiver<(NetlinkMessage<GenericNetlinkMessage>, SocketAddr)>,
)> {
    let (conn, handle, messages) = netlink_proto::new_connection(NETLINK_GENERIC)?;
    Ok((conn, GenericNetlinkHandle::new(handle), messages))
}
