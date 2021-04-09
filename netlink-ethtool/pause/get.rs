use futures::{self, future::Either, FutureExt, StreamExt, TryStream};
use netlink_packet_core::{NetlinkMessage, NLM_F_REQUEST};

use netlink_packet_utils::Emitable; // debug only

use crate::{try_ethtool, EthtoolError, EthtoolHandle, EthtoolMessage};

pub struct PauseGetRequest {
    handle: EthtoolHandle,
    iface_name: String,
}

impl PauseGetRequest {
    pub(crate) fn new(handle: EthtoolHandle, iface_name: &str) -> Self {
        PauseGetRequest {
            handle,
            iface_name: iface_name.to_string(),
        }
    }

    pub fn execute(self) -> impl TryStream<Ok = EthtoolMessage, Error = EthtoolError> {
        let PauseGetRequest {
            mut handle,
            iface_name,
        } = self;

        let ethtool_msg = EthtoolMessage::new_pause_get(handle.family_id, &iface_name);

        println!("ethtool_msg_len: {:?}", ethtool_msg.buffer_len());
        let mut buffer = vec![0; ethtool_msg.buffer_len()];
        ethtool_msg.emit(&mut buffer);
        println!("ethtool_msg: {:?}", buffer);

        let mut nl_msg = NetlinkMessage::from(ethtool_msg);

        nl_msg.header.flags = NLM_F_REQUEST;
        // req.header.message_type = handle.family_id;
        nl_msg.finalize();

        println!("nl_msg_len: {:?}", nl_msg.buffer_len());
        let mut buffer = vec![0; nl_msg.buffer_len()];
        nl_msg.emit(&mut buffer);
        println!("nl_msg: {:?}", buffer);

        match handle.request(nl_msg) {
            Ok(response) => Either::Left(response.map(move |msg| Ok(try_ethtool!(msg)))),
            Err(e) => {
                Either::Right(futures::future::err::<EthtoolMessage, EthtoolError>(e).into_stream())
            }
        }
    }
}
