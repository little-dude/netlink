// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{
    mptcp_execute,
    MptcpPathManagerError,
    MptcpPathManagerHandle,
    MptcpPathManagerMessage,
};

pub struct MptcpPathManagerAddressGetRequest {
    handle: MptcpPathManagerHandle,
}

impl MptcpPathManagerAddressGetRequest {
    pub(crate) fn new(handle: MptcpPathManagerHandle) -> Self {
        MptcpPathManagerAddressGetRequest { handle }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<MptcpPathManagerMessage>, Error = MptcpPathManagerError>
    {
        let MptcpPathManagerAddressGetRequest { mut handle } = self;

        let mptcp_msg = MptcpPathManagerMessage::new_address_get();
        mptcp_execute(&mut handle, mptcp_msg).await
    }
}
