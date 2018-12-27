use failure::{Fail, ResultExt};
use futures::Stream;
use netlink_proto::{ConnectionHandle, SocketAddr};
use packet::NetlinkMessage;

use {AddressHandle, Error, ErrorKind, LinkHandle};

lazy_static! {
    static ref KERNEL_UNICAST: SocketAddr = SocketAddr::new(0, 0);
}

#[derive(Clone, Debug)]
pub struct Handle(ConnectionHandle);

impl Handle {
    pub(crate) fn new(conn: ConnectionHandle) -> Self {
        Handle(conn)
    }

    pub fn request(
        &mut self,
        message: NetlinkMessage,
    ) -> impl Stream<Item = NetlinkMessage, Error = Error> {
        self.0
            .request(message, *KERNEL_UNICAST)
            .map_err(|e| e.context(ErrorKind::RequestFailed).into())
    }

    pub fn notify(&mut self, msg: NetlinkMessage) -> Result<(), Error> {
        self.0
            .notify(msg, *KERNEL_UNICAST)
            .context(ErrorKind::RequestFailed)?;
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
}
