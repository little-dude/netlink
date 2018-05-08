use core::{self, fmt};
use std::error::Error as StdError;

/// The error type for the netlink packet parser
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// An incoming packet could not be parsed because some of its fields were out of bounds
    /// of the received data.
    Truncated,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. an Ethernet packet with an unknown EtherType.
    Unrecognized,
    /// An incoming packet was recognized but was self-contradictory.
    /// E.g. a TCP packet with both SYN and FIN flags set.
    Malformed,
    #[doc(hidden)]
    __Nonexhaustive,
}

pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Exhausted => "buffer space exhausted",
            Error::Truncated => "truncated packet",
            Error::Unrecognized => "unrecognized packet",
            Error::Malformed => "malformed packet",
            Error::__Nonexhaustive => unreachable!(),
        }
    }

    fn cause(&self) -> Option<&StdError> {
        None
    }
}
