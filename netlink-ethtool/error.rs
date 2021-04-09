use thiserror::Error;

use netlink_packet_core::{ErrorMessage, NetlinkMessage};

use crate::EthtoolMessage;

#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum EthtoolError {
    #[error("Received an unexpected message {0:?}")]
    UnexpectedMessage(NetlinkMessage<EthtoolMessage>),

    #[error("Received a netlink error message {0}")]
    NetlinkError(ErrorMessage),

    #[error("A netlink request failed")]
    RequestFailed(String),
}
