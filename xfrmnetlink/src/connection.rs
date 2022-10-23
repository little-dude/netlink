// SPDX-License-Identifier: MIT

use std::io;

use futures::channel::mpsc::UnboundedReceiver;

use crate::{
    packet::{NetlinkMessage, XfrmMessage},
    proto::Connection,
    sys::{protocols::NETLINK_XFRM, AsyncSocket, SocketAddr},
    Handle,
};

#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<XfrmMessage>,
    Handle,
    UnboundedReceiver<(NetlinkMessage<XfrmMessage>, SocketAddr)>,
)> {
    new_connection_with_socket()
}

#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> io::Result<(
    Connection<XfrmMessage, S>,
    Handle,
    UnboundedReceiver<(NetlinkMessage<XfrmMessage>, SocketAddr)>,
)>
where
    S: AsyncSocket,
{
    let (conn, handle, messages) = netlink_proto::new_connection_with_socket(NETLINK_XFRM)?;
    Ok((conn, Handle::new(handle), messages))
}
