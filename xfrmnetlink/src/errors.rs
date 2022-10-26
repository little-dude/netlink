// SPDX-License-Identifier: MIT

use thiserror::Error;

use crate::packet::{ErrorMessage, NetlinkMessage, XfrmMessage};

#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum Error {
    #[error("Received an unexpected message {0:?}")]
    UnexpectedMessage(NetlinkMessage<XfrmMessage>),

    #[error("Received a netlink error message {0}")]
    NetlinkError(ErrorMessage),

    #[error("A netlink request failed")]
    RequestFailed,

    #[error("Failed to parse an IP address: {0:?}")]
    InvalidIp(Vec<u8>),

    #[error("Failed to parse a network address (IP and mask): {0:?}/{1:?}")]
    InvalidAddress(Vec<u8>, Vec<u8>),

    #[error("Invalid algorithm string {0}")]
    AlgName(String),
}
