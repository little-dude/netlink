use futures::Stream;
use genetlink::GenetlinkHandle;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_generic::GenlMessage;
use netlink_packet_utils::DecodeError;

use crate::{EthtoolError, EthtoolFeatureHandle, EthtoolMessage, EthtoolPauseHandle};

#[derive(Clone, Debug)]
pub struct EthtoolHandle {
    pub handle: GenetlinkHandle,
}

impl EthtoolHandle {
    pub(crate) fn new(handle: GenetlinkHandle) -> Self {
        EthtoolHandle { handle }
    }

    pub fn pause(&mut self) -> EthtoolPauseHandle {
        EthtoolPauseHandle::new(self.clone())
    }

    pub fn feature(&mut self) -> EthtoolFeatureHandle {
        EthtoolFeatureHandle::new(self.clone())
    }

    pub async fn request(
        &mut self,
        message: NetlinkMessage<GenlMessage<EthtoolMessage>>,
    ) -> Result<
        impl Stream<Item = Result<NetlinkMessage<GenlMessage<EthtoolMessage>>, DecodeError>>,
        EthtoolError,
    > {
        self.handle
            .request(message)
            .await
            .map_err(|e| EthtoolError::RequestFailed(format!("BUG: Request failed with {}", e)))
    }
}
