// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{
    mptcp_execute,
    MptcpPathManagerError,
    MptcpPathManagerHandle,
    MptcpPathManagerMessage,
};

pub struct MptcpPathManagerLimitsGetRequest {
    handle: MptcpPathManagerHandle,
}

impl MptcpPathManagerLimitsGetRequest {
    pub(crate) fn new(handle: MptcpPathManagerHandle) -> Self {
        MptcpPathManagerLimitsGetRequest { handle }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<MptcpPathManagerMessage>, Error = MptcpPathManagerError>
    {
        let MptcpPathManagerLimitsGetRequest { mut handle } = self;

        let mptcp_msg = MptcpPathManagerMessage::new_limits_get();
        mptcp_execute(&mut handle, mptcp_msg).await
    }
}
