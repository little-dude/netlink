use futures::sync::mpsc::UnboundedSender;
use netlink_packet_core::NetlinkMessage;
use netlink_sys::SocketAddr;
use std::fmt::Debug;

#[derive(Debug)]
pub(crate) struct Request<T>
where
    T: Debug + Clone + Eq + PartialEq,
{
    pub chan: UnboundedSender<NetlinkMessage<T>>,
    pub message: NetlinkMessage<T>,
    pub destination: SocketAddr,
}

impl<T>
    From<(
        UnboundedSender<NetlinkMessage<T>>,
        NetlinkMessage<T>,
        SocketAddr,
    )> for Request<T>
where
    T: Debug + PartialEq + Eq + Clone,
{
    fn from(
        parts: (
            UnboundedSender<NetlinkMessage<T>>,
            NetlinkMessage<T>,
            SocketAddr,
        ),
    ) -> Self {
        Request {
            chan: parts.0,
            message: parts.1,
            destination: parts.2,
        }
    }
}

impl<T>
    Into<(
        UnboundedSender<NetlinkMessage<T>>,
        NetlinkMessage<T>,
        SocketAddr,
    )> for Request<T>
where
    T: Debug + PartialEq + Eq + Clone,
{
    fn into(
        self,
    ) -> (
        UnboundedSender<NetlinkMessage<T>>,
        NetlinkMessage<T>,
        SocketAddr,
    ) {
        (self.chan, self.message, self.destination)
    }
}
