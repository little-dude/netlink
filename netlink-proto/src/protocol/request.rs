// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use futures::channel::mpsc::UnboundedSender;
use netlink_packet_core::NetlinkMessage;

use crate::sys::SocketAddr;

#[derive(Debug)]
pub(crate) struct Request<T> {
    pub response_tx: UnboundedSender<NetlinkMessage<T>>,
    pub message: NetlinkMessage<T>,
    pub destination: SocketAddr,
}

impl<T> From<(NetlinkMessage<T>, SocketAddr, UnboundedSender<NetlinkMessage<T>>)> for Request<T>
where
    T: Debug,
{
    fn from(parts: (NetlinkMessage<T>, SocketAddr, UnboundedSender<NetlinkMessage<T>>)) -> Self {
        Request {
            message: parts.0,
            destination: parts.1,
            response_tx: parts.2,
        }
    }
}

impl<T> From<Request<T>> for (NetlinkMessage<T>, SocketAddr, UnboundedSender<NetlinkMessage<T>>)
where
    T: Debug,
{
    fn from(req: Request<T>) -> (NetlinkMessage<T>, SocketAddr, UnboundedSender<NetlinkMessage<T>>) {
        (req.message, req.destination, req.response_tx)
    }
}
