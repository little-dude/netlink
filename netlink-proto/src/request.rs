use futures::sync::mpsc::UnboundedSender;
use netlink_packet::NetlinkMessage;
use netlink_sys::SocketAddr;

#[derive(Debug)]
pub(crate) struct Request {
    pub chan: UnboundedSender<NetlinkMessage>,
    pub message: NetlinkMessage,
    pub destination: SocketAddr,
}

impl From<(UnboundedSender<NetlinkMessage>, NetlinkMessage, SocketAddr)> for Request {
    fn from(parts: (UnboundedSender<NetlinkMessage>, NetlinkMessage, SocketAddr)) -> Self {
        Request {
            chan: parts.0,
            message: parts.1,
            destination: parts.2,
        }
    }
}

impl Into<(UnboundedSender<NetlinkMessage>, NetlinkMessage, SocketAddr)> for Request {
    fn into(self) -> (UnboundedSender<NetlinkMessage>, NetlinkMessage, SocketAddr) {
        (self.chan, self.message, self.destination)
    }
}
