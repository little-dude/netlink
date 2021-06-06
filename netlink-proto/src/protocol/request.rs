use std::fmt::Debug;

use netlink_packet_core::NetlinkMessage;

use crate::sys::SocketAddr;

#[derive(Debug)]
pub enum Request<T, M>
where
    T: Debug + Clone + Eq + PartialEq,
    M: Debug,
{
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
