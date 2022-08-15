// SPDX-License-Identifier: MIT

use futures::{future::Either, FutureExt, Stream, StreamExt, TryStream};
use genetlink::GenetlinkHandle;
use netlink_packet_core::{NetlinkMessage, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_utils::DecodeError;

use crate::{try_nl80211, Nl80211Error, Nl80211InterfaceHandle, Nl80211Message};

#[derive(Clone, Debug)]
pub struct Nl80211Handle {
    pub handle: GenetlinkHandle,
}

impl Nl80211Handle {
    pub(crate) fn new(handle: GenetlinkHandle) -> Self {
        Nl80211Handle { handle }
    }

    // equivalent to `iw dev` command
    pub fn interface(&self) -> Nl80211InterfaceHandle {
        Nl80211InterfaceHandle::new(self.clone())
    }

    pub async fn request(
        &mut self,
        message: NetlinkMessage<GenlMessage<Nl80211Message>>,
    ) -> Result<
        impl Stream<Item = Result<NetlinkMessage<GenlMessage<Nl80211Message>>, DecodeError>>,
        Nl80211Error,
    > {
        self.handle
            .request(message)
            .await
            .map_err(|e| Nl80211Error::RequestFailed(format!("BUG: Request failed with {}", e)))
    }
}

pub(crate) async fn nl80211_execute(
    handle: &mut Nl80211Handle,
    nl80211_msg: Nl80211Message,
) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error> {
    let nl_header_flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut nl_msg = NetlinkMessage::from(GenlMessage::from_payload(nl80211_msg));

    nl_msg.header.flags = nl_header_flags;

    match handle.request(nl_msg).await {
        Ok(response) => Either::Left(response.map(move |msg| Ok(try_nl80211!(msg)))),
        Err(e) => Either::Right(
            futures::future::err::<GenlMessage<Nl80211Message>, Nl80211Error>(e).into_stream(),
        ),
    }
}
