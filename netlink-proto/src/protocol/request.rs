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
