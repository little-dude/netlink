// SPDX-License-Identifier: MIT

#[macro_export]
macro_rules! try_nl80211 {
    ($msg: expr) => {{
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use $crate::Nl80211Error;

        match $msg {
            Ok(msg) => {
                let (header, payload) = msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(msg) => msg,
                    NetlinkPayload::Error(err) => return Err(Nl80211Error::NetlinkError(err)),
                    _ => {
                        return Err(Nl80211Error::UnexpectedMessage(NetlinkMessage::new(
                            header, payload,
                        )))
                    }
                }
            }
            Err(e) => return Err(Nl80211Error::Bug(format!("BUG: decode error {:?}", e))),
        }
    }};
}
