use futures::{self, future::Either, FutureExt, StreamExt, TryStream};
use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{try_ethtool, EthtoolError, EthtoolHandle, EthtoolMessage};

pub struct EthtoolFeatureGetRequest {
    handle: EthtoolHandle,
    iface_name: Option<String>,
}

impl EthtoolFeatureGetRequest {
    pub(crate) fn new(handle: EthtoolHandle, iface_name: Option<&str>) -> Self {
        EthtoolFeatureGetRequest {
            handle,
            iface_name: iface_name.map(|i| i.to_string()),
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<EthtoolMessage>, Error = EthtoolError> {
        let EthtoolFeatureGetRequest {
            mut handle,
            iface_name,
        } = self;

        let nl_header_flags = match iface_name {
            // The NLM_F_ACK is required due to bug of kernel:
            //  https://bugzilla.redhat.com/show_bug.cgi?id=1953847
            // without `NLM_F_MULTI`, rust-netlink will not parse
            // multiple netlink message in single socket reply.
            // Using NLM_F_ACK will force rust-netlink to parse all till
            // acked at the end.
            None => NLM_F_DUMP | NLM_F_REQUEST | NLM_F_ACK,
            Some(_) => NLM_F_REQUEST,
        };

        let ethtool_msg = EthtoolMessage::new_feature_get(iface_name.as_deref());

        let mut nl_msg = NetlinkMessage::from(GenlMessage::from_payload(ethtool_msg));

        nl_msg.header.flags = nl_header_flags;

        match handle.request(nl_msg).await {
            Ok(response) => Either::Left(response.map(move |msg| Ok(try_ethtool!(msg)))),
            Err(e) => Either::Right(
                futures::future::err::<GenlMessage<EthtoolMessage>, EthtoolError>(e).into_stream(),
            ),
        }
    }
}
