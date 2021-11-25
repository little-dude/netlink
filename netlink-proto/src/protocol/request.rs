// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::NetlinkMessage;

use crate::sys::SocketAddr;

#[derive(Debug)]
pub(crate) enum Request<T, M> {
    Single {
        metadata: M,
        message: NetlinkMessage<T>,
        destination: SocketAddr,
    },
    Batch {
        metadata: Vec<M>,
        messages: Vec<NetlinkMessage<T>>,
        destination: SocketAddr,
    },
}
