// SPDX-License-Identifier: MIT

#[macro_export]
macro_rules! try_mptcp {
    ($msg: expr) => {{
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use $crate::MptcpPathManagerError;

        match $msg {
            Ok(msg) => {
                let (header, payload) = msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(msg) => msg,
                    NetlinkPayload::Error(err) => {
                        return Err(MptcpPathManagerError::NetlinkError(err))
                    }
                    _ => {
                        return Err(MptcpPathManagerError::UnexpectedMessage(
                            NetlinkMessage::new(header, payload),
                        ))
                    }
                }
            }
            Err(e) => {
                return Err(MptcpPathManagerError::Bug(format!(
                    "BUG: decode error {:?}",
                    e
                )))
            }
        }
    }};
}
