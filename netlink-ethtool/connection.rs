use std::io;

use futures::channel::mpsc::UnboundedReceiver;
use netlink_packet_core::NetlinkMessage;
use netlink_proto::{self, Connection};
use netlink_sys::{constants::NETLINK_GENERIC, SocketAddr};

use crate::{EthtoolHandle, EthtoolMessage};

#[allow(clippy::type_complexity)]
pub fn new_connection(
    family_id: u16,
) -> io::Result<(
    Connection<EthtoolMessage>,
    EthtoolHandle,
    UnboundedReceiver<(NetlinkMessage<EthtoolMessage>, SocketAddr)>,
)> {
    let (conn, handle, messages) = netlink_proto::new_connection(NETLINK_GENERIC)?;
    Ok((conn, EthtoolHandle::new(handle, family_id), messages))
}
