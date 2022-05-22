// SPDX-License-Identifier: MIT

use futures::{future::Either, FutureExt, Stream, StreamExt, TryStream};
use genetlink::GenetlinkHandle;
use netlink_packet_core::{NetlinkMessage, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_utils::DecodeError;

use crate::{
    try_mptcp,
    MptcpPathManagerAddressHandle,
    MptcpPathManagerCmd,
    MptcpPathManagerError,
    MptcpPathManagerLimitsHandle,
    MptcpPathManagerMessage,
};

#[derive(Clone, Debug)]
pub struct MptcpPathManagerHandle {
    pub handle: GenetlinkHandle,
}

impl MptcpPathManagerHandle {
    pub(crate) fn new(handle: GenetlinkHandle) -> Self {
        MptcpPathManagerHandle { handle }
    }

    // equivalent to `ip mptcp endpoint` command
    // Instead of using `endpoint`, we are aligning with kernel netlink name
    // `address` here.
    pub fn address(&self) -> MptcpPathManagerAddressHandle {
        MptcpPathManagerAddressHandle::new(self.clone())
    }

    // equivalent to `ip mptcp limits` command
    pub fn limits(&self) -> MptcpPathManagerLimitsHandle {
        MptcpPathManagerLimitsHandle::new(self.clone())
    }

    pub async fn request(
        &mut self,
        message: NetlinkMessage<GenlMessage<MptcpPathManagerMessage>>,
    ) -> Result<
        impl Stream<Item = Result<NetlinkMessage<GenlMessage<MptcpPathManagerMessage>>, DecodeError>>,
        MptcpPathManagerError,
    > {
        self.handle.request(message).await.map_err(|e| {
            MptcpPathManagerError::RequestFailed(format!("BUG: Request failed with {}", e))
        })
    }
}

pub(crate) async fn mptcp_execute(
    handle: &mut MptcpPathManagerHandle,
    mptcp_msg: MptcpPathManagerMessage,
) -> impl TryStream<Ok = GenlMessage<MptcpPathManagerMessage>, Error = MptcpPathManagerError> {
    let nl_header_flags = match mptcp_msg.cmd {
        MptcpPathManagerCmd::AddressGet => NLM_F_REQUEST | NLM_F_DUMP,
        MptcpPathManagerCmd::LimitsGet => NLM_F_REQUEST,
    };

    let mut nl_msg = NetlinkMessage::from(GenlMessage::from_payload(mptcp_msg));

    nl_msg.header.flags = nl_header_flags;

    match handle.request(nl_msg).await {
        Ok(response) => Either::Left(response.map(move |msg| Ok(try_mptcp!(msg)))),
        Err(e) => Either::Right(
            futures::future::err::<GenlMessage<MptcpPathManagerMessage>, MptcpPathManagerError>(e)
                .into_stream(),
        ),
    }
}
