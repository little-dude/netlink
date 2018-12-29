use std::error::Error as StdError;
use std::fmt;
use std::io;

use netlink_packet::NetlinkMessage;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn into_inner(self) -> ErrorKind {
        self.kind
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    /// The netlink connection is closed
    ConnectionClosed,

    /// Received an error message as a response
    NetlinkError(NetlinkMessage),

    /// Error while reading from or writing to the netlink socket
    SocketIo(io::Error),
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { kind }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::ErrorKind::*;
        match self.kind() {
            SocketIo(ref e) => write!(f, "{}: {}", self.description(), e),
            ConnectionClosed => write!(f, "{}", self.description()),
            NetlinkError(ref message) => write!(f, "{}: {:?}", self.description(), message),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        use crate::ErrorKind::*;
        match self.kind() {
            SocketIo(_) => "Error while reading from or writing to the netlink socket",
            ConnectionClosed => "The netlink connection is closed",
            NetlinkError(_) => "Received an error message as a response",
        }
    }

    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        if let ErrorKind::SocketIo(ref e) = self.kind() {
            Some(e)
        } else {
            None
        }
    }
}
