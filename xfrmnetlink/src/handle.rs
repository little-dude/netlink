// SPDX-License-Identifier: MIT

use futures::Stream;

use crate::{
    packet::{NetlinkMessage, XfrmMessage},
    Error, PolicyHandle, StateHandle,
};
use netlink_proto::{sys::SocketAddr, ConnectionHandle};

#[derive(Clone, Debug)]
pub struct Handle(ConnectionHandle<XfrmMessage>);

impl Handle {
    pub(crate) fn new(conn: ConnectionHandle<XfrmMessage>) -> Self {
        Handle(conn)
    }

    pub fn request(
        &mut self,
        message: NetlinkMessage<XfrmMessage>,
    ) -> Result<impl Stream<Item = NetlinkMessage<XfrmMessage>>, Error> {
        self.0
            .request(message, SocketAddr::new(0, 0))
            .map_err(|_| Error::RequestFailed)
    }

    pub fn notify(&mut self, msg: NetlinkMessage<XfrmMessage>) -> Result<(), Error> {
        self.0
            .notify(msg, SocketAddr::new(0, 0))
            .map_err(|_| Error::RequestFailed)?;
        Ok(())
    }

    /// Create a new handle, specifically for policy requests (equivalent to `ip xfrm policy` commands)
    pub fn policy(&self) -> PolicyHandle {
        PolicyHandle::new(self.clone())
    }

    /// Create a new handle, specifically for state requests (equivalent to `ip xfrm state` commands)
    pub fn state(&self) -> StateHandle {
        StateHandle::new(self.clone())
    }
}
