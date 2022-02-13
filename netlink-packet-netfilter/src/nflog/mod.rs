// SPDX-License-Identifier: MIT

mod message;
pub use message::NfLogMessage;
pub mod nlas;

use crate::{
    constants::NFNETLINK_V0,
    nflog::nlas::config::ConfigNla,
    nl::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST},
    NetfilterHeader,
    NetfilterMessage,
};

pub fn config_request(
    family: u8,
    group_num: u16,
    nlas: Vec<ConfigNla>,
) -> NetlinkMessage<NetfilterMessage> {
    let mut message = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_ACK,
            ..Default::default()
        },
        payload: NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, group_num),
            NfLogMessage::Config(nlas),
        )),
    };
    message.finalize();
    message
}
