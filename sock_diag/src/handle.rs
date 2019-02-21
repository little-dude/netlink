use failure::{Error, Fail, ResultExt};
use futures::Stream;
use netlink_proto::{ConnectionHandle, SocketAddr};

use crate::packet::NetlinkMessage;
use crate::{ErrorKind, InetHandle, PacketHandle, UnixHandle};

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

    /// Create a new handle, specifically for inet requests (equivalent to `ss -4 -6` commands)
    pub fn inet(&self) -> InetHandle {
        InetHandle::new(self.clone())
    }

    /// Create a new handle, specifically for unix requests (equivalent to `ss --unix` commands)
    pub fn unix(&self) -> UnixHandle {
        UnixHandle::new(self.clone())
    }

    /// Create a new handle, specifically for packet requests (equivalent to `ss --packet` commands)
    pub fn packet(&self) -> PacketHandle {
        PacketHandle::new(self.clone())
    }
}
