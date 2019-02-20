use failure::Fail;

use crate::packet::{ErrorMessage, NetlinkMessage};

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Received an unexpected message {:?}", _0)]
    UnexpectedMessage(NetlinkMessage),

    #[fail(display = "Received a netlink error message {:?}", _0)]
    NetlinkError(ErrorMessage),

    #[fail(display = "A netlink request failed")]
    RequestFailed,
}
