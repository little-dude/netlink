use std::io;

use futures::channel::mpsc::UnboundedReceiver;
use genetlink::message::RawGenlMessage;
use netlink_packet_core::NetlinkMessage;
use netlink_proto::Connection;
use netlink_sys::SocketAddr;

use crate::EthtoolHandle;

#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<RawGenlMessage>,
    EthtoolHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)> {
    let (conn, handle, messages) = genetlink::new_connection()?;
    Ok((conn, EthtoolHandle::new(handle), messages))
}
