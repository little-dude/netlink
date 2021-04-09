use futures::Stream;
use netlink_packet_core::NetlinkMessage;
use netlink_proto::{sys::SocketAddr, ConnectionHandle};

use crate::{EthtoolError, EthtoolMessage, PauseHandle};

#[derive(Clone, Debug)]
pub struct EthtoolHandle {
    pub family_id: u16,
    pub handle: ConnectionHandle<EthtoolMessage>,
}

impl EthtoolHandle {
    pub(crate) fn new(handle: ConnectionHandle<EthtoolMessage>, family_id: u16) -> Self {
        EthtoolHandle { family_id, handle }
    }

    pub fn pause(&mut self) -> PauseHandle {
        PauseHandle::new(self.clone())
    }

    pub fn request(
        &mut self,
        message: NetlinkMessage<EthtoolMessage>,
    ) -> Result<impl Stream<Item = NetlinkMessage<EthtoolMessage>>, EthtoolError> {
        self.handle
            .request(message, SocketAddr::new(0, 0))
            .map_err(|e| EthtoolError::RequestFailed(format!("BUG: Request failed with {}", e)))
    }
}
