use futures::channel::mpsc::UnboundedReceiver;
use std::io;

use crate::{
    packet::{netlink::NetlinkMessage, rtnl::RtnlMessage},
    Handle,
};
use netlink_proto::{
    sys::{Protocol, SocketAddr},
    Connection,
};

#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<RtnlMessage>,
    Handle,
    UnboundedReceiver<(NetlinkMessage<RtnlMessage>, SocketAddr)>,
)> {
    let (conn, handle, messages) = netlink_proto::new_connection(Protocol::Route)?;
    Ok((conn, Handle::new(handle), messages))
}
