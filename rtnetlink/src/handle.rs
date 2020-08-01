use futures::Stream;

use crate::{
    packet::{NetlinkMessage, RtnlMessage},
    AddressHandle, Error, LinkHandle, QDiscHandle, RouteHandle, TrafficClassHandle,
};
use netlink_proto::{sys::SocketAddr, ConnectionHandle};

#[derive(Clone, Debug)]
pub struct Handle(ConnectionHandle<RtnlMessage>);

impl Handle {
    pub(crate) fn new(conn: ConnectionHandle<RtnlMessage>) -> Self {
        Handle(conn)
    }

    pub fn request(
        &mut self,
        message: NetlinkMessage<RtnlMessage>,
    ) -> Result<impl Stream<Item = NetlinkMessage<RtnlMessage>>, Error> {
        self.0
            .request(message, SocketAddr::new(0, 0))
            .map_err(|_| Error::RequestFailed)
    }

    pub fn notify(&mut self, msg: NetlinkMessage<RtnlMessage>) -> Result<(), Error> {
        self.0
            .notify(msg, SocketAddr::new(0, 0))
            .map_err(|_| Error::RequestFailed)?;
        Ok(())
    }

    /// Create a new handle, specifically for link requests (equivalent to `ip link` commands)
    pub fn link(&self) -> LinkHandle {
        LinkHandle::new(self.clone())
    }

    /// Create a new handle, specifically for address requests (equivalent to `ip addr` commands)
    pub fn address(&self) -> AddressHandle {
        AddressHandle::new(self.clone())
    }

    /// Create a new handle, specifically for routing table requests (equivalent to `ip route` commands)
    pub fn route(&self) -> RouteHandle {
        RouteHandle::new(self.clone())
    }

    /// Create a new handle, specifically for traffic control qdisc requests
    /// (equivalent to `tc qdisc show` commands)
    pub fn qdisc(&self) -> QDiscHandle {
        QDiscHandle::new(self.clone())
    }

    /// Create a new handle, specifically for traffic control qdisc requests
    /// (equivalent to `tc class show` commands)
    pub fn traffic_class(&self, ifindex: i32) -> TrafficClassHandle {
        TrafficClassHandle::new(self.clone(), ifindex)
    }
}
