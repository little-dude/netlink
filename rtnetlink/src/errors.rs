use std::fmt::{self, Display};

use failure::{Backtrace, Context, Fail};

use crate::packet::{ErrorMessage, NetlinkMessage, RtnlMessage};

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Received an unexpected message {:?}", _0)]
    UnexpectedMessage(NetlinkMessage<RtnlMessage>),

    #[fail(display = "Received a netlink error message {}", _0)]
    NetlinkError(ErrorMessage),

    #[fail(display = "A netlink request failed")]
    RequestFailed,

    #[fail(
        display = "Received a link message (RTM_GETLINK, RTM_NEWLINK, RTM_SETLINK or RTMGETLINK) with an invalid hardware address attribute: {:?}.",
        _0
    )]
    InvalidHardwareAddress(Vec<u8>),

    #[fail(display = "Failed to parse an IP address: {:?}", _0)]
    InvalidIp(Vec<u8>),

    #[fail(
        display = "Failed to parse a network address (IP and mask): {:?}/{:?}",
        _0, _1
    )]
    InvalidAddress(Vec<u8>, Vec<u8>),
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.inner.get_context().clone()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Self {
        Error { inner }
    }
}
