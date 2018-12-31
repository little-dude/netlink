use crate::constants::*;
use failure::ResultExt;

use crate::{
    AckMessage, DecodeError, Emitable, EncodeError, ErrorBuffer, ErrorMessage, NetlinkBuffer,
    NetlinkHeader, Parseable,
};

#[cfg(feature = "rtnetlink")]
use crate::RtnlMessage;

#[cfg(feature = "audit")]
use crate::AuditMessage;

/// Represent a netlink message.
///
/// A netlink message is made of a header (represented by
/// [`NetlinkHeader`](struct.NetlinkHeader.html)) and message (represented by
/// [`NetlinkPayload`](enum.NetlinkPayload.html)):
///
/// ```no_rust
/// 0                8                16              24               32
/// +----------------+----------------+----------------+----------------+
/// |                 packet length (including header)                  |   \
/// +----------------+----------------+----------------+----------------+    |
/// |          message type           |              flags              |    |
/// +----------------+----------------+----------------+----------------+    | NetlinkHeader
/// |                           sequence number                         |    |
/// +----------------+----------------+----------------+----------------+    |
/// |                   port number (formerly known as PID)             |   /
/// +----------------+----------------+----------------+----------------+   
/// |                               payload                             |   \
/// |                          (variable length)                        |    |  NetlinkPayload
/// |                                                                   |    |
/// |                                                                   |   /
/// +----------------+----------------+----------------+----------------+
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NetlinkMessage {
    header: NetlinkHeader,
    payload: NetlinkPayload,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NetlinkPayload {
    Done,
    Error(ErrorMessage),
    Ack(AckMessage),
    Noop,
    Overrun(Vec<u8>),
    #[cfg(feature = "rtnetlink")]
    Rtnl(RtnlMessage),
    #[cfg(feature = "audit")]
    Audit(AuditMessage),
    #[cfg(not(any(feature = "rtnetlink", feature = "audit")))]
    #[doc(hidden)]
    __Default,
}

impl NetlinkPayload {
    pub fn message_type(&self) -> u16 {
        use self::NetlinkPayload::*;

        match self {
            Noop => NLMSG_NOOP,
            Done => NLMSG_DONE,
            Error(_) | Ack(_) => NLMSG_ERROR,
            Overrun(_) => NLMSG_OVERRUN,
            #[cfg(feature = "rtnetlink")]
            Rtnl(ref msg) => msg.message_type(),
            #[cfg(feature = "audit")]
            Audit(ref msg) => msg.message_type(),
            #[cfg(not(any(feature = "rtnetlink", feature = "audit")))]
            _ => 0,
        }
    }

    #[cfg(feature = "rtnetlink")]
    pub fn is_rtnl(&self) -> bool {
        if let NetlinkPayload::Rtnl(_) = *self {
            true
        } else {
            false
        }
    }

    #[cfg(feature = "audit")]
    pub fn is_audit(&self) -> bool {
        if let NetlinkPayload::Audit(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_done(&self) -> bool {
        *self == NetlinkPayload::Done
    }

    pub fn is_noop(&self) -> bool {
        *self == NetlinkPayload::Noop
    }

    pub fn is_overrun(&self) -> bool {
        if let NetlinkPayload::Overrun(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_error(&self) -> bool {
        if let NetlinkPayload::Error(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_ack(&self) -> bool {
        if let NetlinkPayload::Ack(_) = *self {
            true
        } else {
            false
        }
    }
}

impl From<NetlinkPayload> for NetlinkMessage {
    fn from(payload: NetlinkPayload) -> Self {
        NetlinkMessage {
            header: NetlinkHeader::default(),
            payload,
        }
    }
}

#[cfg(feature = "rtnetlink")]
impl From<RtnlMessage> for NetlinkMessage {
    fn from(msg: RtnlMessage) -> Self {
        NetlinkMessage::from(NetlinkPayload::Rtnl(msg))
    }
}

#[cfg(feature = "audit")]
impl From<AuditMessage> for NetlinkMessage {
    fn from(msg: AuditMessage) -> Self {
        NetlinkMessage::from(NetlinkPayload::Audit(msg))
    }
}

impl NetlinkMessage {
    pub fn new(header: NetlinkHeader, payload: NetlinkPayload) -> Self {
        NetlinkMessage { header, payload }
    }

    pub fn into_parts(self) -> (NetlinkHeader, NetlinkPayload) {
        (self.header, self.payload)
    }

    pub fn payload(&self) -> &NetlinkPayload {
        &self.payload
    }

    pub fn payload_mut(&mut self) -> &mut NetlinkPayload {
        &mut self.payload
    }

    pub fn header(&self) -> &NetlinkHeader {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut NetlinkHeader {
        &mut self.header
    }

    /// Safely serialize the message. Under the hood, this calls
    /// [`Emitable::emit()`](trait.Emitable.html#tymethod.emit), but unlike `emit()`, this method
    /// does not panic if the message is malformed or if the destination buffer is too small.
    /// Instead, an error is returned.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        self.finalize();
        if self.header().length() as usize > buffer.len() {
            Err(EncodeError::from("buffer exhausted"))
        } else {
            self.emit(buffer);
            Ok(self.header().length() as usize)
        }
    }

    /// Try to parse a message from a buffer
    pub fn from_bytes(buffer: &[u8]) -> Result<Self, DecodeError> {
        Ok(NetlinkBuffer::new_checked(&buffer)
            .context("failed to parse netlink packet")?
            .parse()
            .context("failed to parse netlink packet")?)
    }

    /// Check if the payload is a `NLMSG_DONE` message
    /// ([`Rtnl::Done`](enum.NetlinkPayload.html#variant.Done))
    pub fn is_done(&self) -> bool {
        self.payload().is_done()
    }

    /// Check if the payload is a `NLMSG_NOOP` message
    /// ([`Rtnl::Noop`](enum.NetlinkPayload.html#variant.Noop))
    pub fn is_noop(&self) -> bool {
        self.payload().is_noop()
    }

    /// Check if the payload is a `NLMSG_OVERRUN` message
    /// ([`Rtnl::Overrun`](enum.NetlinkPayload.html#variant.Overrun))
    pub fn is_overrun(&self) -> bool {
        self.payload().is_overrun()
    }

    /// Check if the payload is a `NLMSG_ERROR` message with a negative error code
    /// ([`Rtnl::Error`](enum.NetlinkPayload.html#variant.Error))
    pub fn is_error(&self) -> bool {
        self.payload().is_error()
    }

    /// Check if the payload is a `NLMSG_ERROR` message with a non-negative error code
    /// ([`Rtnl::Ack`](enum.NetlinkPayload.html#variant.Ack))
    pub fn is_ack(&self) -> bool {
        self.payload().is_ack()
    }

    #[cfg(feature = "rtnetlink")]
    pub fn is_rtnl(&self) -> bool {
        self.payload().is_rtnl()
    }

    #[cfg(feature = "audit")]
    pub fn is_audit(&self) -> bool {
        self.payload().is_audit()
    }

    /// Ensure the header (`NetlinkHeader`) is consistent with the payload (`NetlinkPayload`):
    ///
    /// - compute the payload length and set the header's length field
    /// - check the payload type and set the header's message type field accordingly
    ///
    /// If you are not 100% sure the header is correct, this method should be called before calling
    /// [`Emitable::emit()`](trait.Emitable.html#tymethod.emit) or
    /// [`to_bytes()`](#method.to_bytes). `emit()` could panic if the header is inconsistent with
    /// the rest of the message, and `to_bytes()` would return an error.
    pub fn finalize(&mut self) {
        *self.header.length_mut() = self.buffer_len() as u32;
        *self.header.message_type_mut() = self.payload.message_type();
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NetlinkMessage> for NetlinkBuffer<&'buffer T> {
    fn parse(&self) -> Result<NetlinkMessage, DecodeError> {
        use self::NetlinkPayload::*;
        let header = <Self as Parseable<NetlinkHeader>>::parse(self)
            .context("failed to parse netlink header")?;

        let payload = match header.message_type() {
            NLMSG_ERROR => {
                let msg: ErrorMessage = ErrorBuffer::new(&self.payload())
                    .parse()
                    .context("failed to parse NLMSG_ERROR")?;
                if msg.code >= 0 {
                    Ack(msg as AckMessage)
                } else {
                    Error(msg)
                }
            }
            NLMSG_NOOP => Noop,
            NLMSG_DONE => Done,

            #[cfg(feature = "rtnetlink")]
            message_type => {
                NetlinkPayload::Rtnl(RtnlMessage::parse(message_type, &self.payload())?)
            }

            #[cfg(feature = "audit")]
            message_type => {
                NetlinkPayload::Audit(AuditMessage::parse(message_type, &self.payload())?)
            }

            #[cfg(not(any(feature = "rtnetlink", feature = "audit")))]
            _ => __Default,
        };
        Ok(NetlinkMessage { header, payload })
    }
}

impl Emitable for NetlinkMessage {
    fn buffer_len(&self) -> usize {
        use self::NetlinkPayload::*;
        let payload_len = match self.payload {
            Noop | Done => 0,
            Overrun(ref bytes) => bytes.len(),
            Error(ref msg) => msg.buffer_len(),
            Ack(ref msg) => msg.buffer_len(),

            #[cfg(feature = "rtnetlink")]
            Rtnl(ref msg) => msg.buffer_len(),

            #[cfg(feature = "audit")]
            Audit(ref msg) => msg.buffer_len(),

            #[cfg(not(any(feature = "rtnetlink", feature = "audit")))]
            __Default => 0,
        };

        self.header.buffer_len() + payload_len
    }

    fn emit(&self, buffer: &mut [u8]) {
        use self::NetlinkPayload::*;

        self.header.emit(buffer);

        let buffer = &mut buffer[self.header.buffer_len()..];
        match self.payload {
            Noop | Done => {}
            Overrun(ref bytes) => buffer.copy_from_slice(bytes),
            Error(ref msg) => msg.emit(buffer),
            Ack(ref msg) => msg.emit(buffer),

            #[cfg(feature = "rtnetlink")]
            Rtnl(ref msg) => msg.emit(buffer),

            #[cfg(feature = "audit")]
            Audit(ref msg) => msg.emit(buffer),

            #[cfg(not(any(feature = "rtnetlink", feature = "audit")))]
            __Default => {}
        }
    }
}
