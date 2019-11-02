use failure::{Fail, ResultExt};
use futures::Stream;

use crate::{
    packet::{NetlinkMessage, RtnlMessage},
    AddressHandle, Error, ErrorKind, LinkHandle,
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
            .map_err(|e| e.context(ErrorKind::RequestFailed).into())
    }

    pub fn notify(&mut self, msg: NetlinkMessage<RtnlMessage>) -> Result<(), Error> {
        self.0
            .notify(msg, SocketAddr::new(0, 0))
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
