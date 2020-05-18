use thiserror::Error;

use crate::packet::{AuditMessage, ErrorMessage, NetlinkMessage};

#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum Error {
    #[error("Received an unexpected message {0:?}")]
    UnexpectedMessage(NetlinkMessage<AuditMessage>),

    #[error("Received a netlink error message {0:?}")]
    NetlinkError(ErrorMessage),

    #[error("Request failed")]
    RequestFailed,
}
