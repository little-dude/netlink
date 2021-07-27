#[macro_export]
macro_rules! try_genl {
    ($msg: expr) => {{
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use $crate::GenericNetlinkError;

        let (header, payload) = $msg.into_parts();
        match payload {
            NetlinkPayload::InnerMessage(msg) => msg,
            NetlinkPayload::Error(err) => return Err(GenericNetlinkError::NetlinkError(err)),
            _ => {
                return Err(GenericNetlinkError::UnexpectedMessage(NetlinkMessage::new(
                    header, payload,
                )))
            }
        }
    }};
}
