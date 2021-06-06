use thiserror::Error;

use netlink_packet_core::{ErrorMessage, NetlinkMessage};

use crate::GenericNetlinkMessage;

#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum GenericNetlinkError {
    #[error("Received an unexpected message {0:?}")]
    UnexpectedMessage(NetlinkMessage<GenericNetlinkMessage>),

    #[error("Received a netlink error message {0}")]
    NetlinkError(ErrorMessage),

    #[error("A netlink request failed")]
    RequestFailed(String),
}
