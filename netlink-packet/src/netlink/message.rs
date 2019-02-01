use crate::constants::*;
use failure::ResultExt;

use crate::{
    AckMessage, DecodeError, Emitable, ErrorBuffer, ErrorMessage, NetlinkBuffer, NetlinkHeader,
    Parseable,
};

#[cfg(feature = "rtnetlink")]
use crate::RtnlMessage;

#[cfg(feature = "audit")]
use crate::AuditMessage;

#[cfg(feature = "sock_diag")]
use crate::SockDiagMessage;

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
    pub header: NetlinkHeader,
    pub payload: NetlinkPayload,
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
    #[cfg(feature = "sock_diag")]
    SockDiag(SockDiagMessage),
    #[cfg(not(any(feature = "rtnetlink", feature = "audit", feature = "sock_diag")))]
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
            #[cfg(feature = "sock_diag")]
            SockDiag(ref msg) => msg.message_type(),
            #[cfg(not(any(feature = "rtnetlink", feature = "audit", feature = "sock_diag")))]
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

    #[cfg(feature = "sock_diag")]
    pub fn is_sock_diag(&self) -> bool {
        if let NetlinkPayload::SockDiag(_) = *self {
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

#[cfg(feature = "sock_diag")]
impl From<SockDiagMessage> for NetlinkMessage {
    fn from(msg: SockDiagMessage) -> Self {
        NetlinkMessage::from(NetlinkPayload::SockDiag(msg))
    }
}

impl NetlinkMessage {
    pub fn new(header: NetlinkHeader, payload: NetlinkPayload) -> Self {
        NetlinkMessage { header, payload }
    }

    pub fn into_parts(self) -> (NetlinkHeader, NetlinkPayload) {
        (self.header, self.payload)
    }

    /// Check if the payload is a `NLMSG_DONE` message
    /// ([`Rtnl::Done`](enum.NetlinkPayload.html#variant.Done))
    pub fn is_done(&self) -> bool {
        self.payload.is_done()
    }

    /// Check if the payload is a `NLMSG_NOOP` message
    /// ([`Rtnl::Noop`](enum.NetlinkPayload.html#variant.Noop))
    pub fn is_noop(&self) -> bool {
        self.payload.is_noop()
    }

    /// Check if the payload is a `NLMSG_OVERRUN` message
    /// ([`Rtnl::Overrun`](enum.NetlinkPayload.html#variant.Overrun))
    pub fn is_overrun(&self) -> bool {
        self.payload.is_overrun()
    }

    /// Check if the payload is a `NLMSG_ERROR` message with a negative error code
    /// ([`Rtnl::Error`](enum.NetlinkPayload.html#variant.Error))
    pub fn is_error(&self) -> bool {
        self.payload.is_error()
    }

    /// Check if the payload is a `NLMSG_ERROR` message with a non-negative error code
    /// ([`Rtnl::Ack`](enum.NetlinkPayload.html#variant.Ack))
    pub fn is_ack(&self) -> bool {
        self.payload.is_ack()
    }

    #[cfg(feature = "rtnetlink")]
    pub fn is_rtnl(&self) -> bool {
        self.payload.is_rtnl()
    }

    #[cfg(feature = "audit")]
    pub fn is_audit(&self) -> bool {
        self.payload.is_audit()
    }

    /// Ensure the header (`NetlinkHeader`) is consistent with the payload (`NetlinkPayload`):
    ///
    /// - compute the payload length and set the header's length field
    /// - check the payload type and set the header's message type field accordingly
    ///
    /// If you are not 100% sure the header is correct, this method should be called before calling
    /// [`Emitable::emit()`](trait.Emitable.html#tymethod.emit), as it could panic if the header is
    /// inconsistent with the rest of the message.
    pub fn finalize(&mut self) {
        self.header.length = self.buffer_len() as u32;
        self.header.message_type = self.payload.message_type();
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NetlinkMessage> for NetlinkBuffer<&'buffer T> {
    fn parse(&self) -> Result<NetlinkMessage, DecodeError> {
        use self::NetlinkPayload::*;
        let header = <Self as Parseable<NetlinkHeader>>::parse(self)
            .context("failed to parse netlink header")?;

        let payload = match header.message_type {
            NLMSG_ERROR => {
                let msg: ErrorMessage = ErrorBuffer::new_checked(&self.payload())
                    .context("failed to parse NLMSG_ERROR")?
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

            #[cfg(feature = "sock_diag")]
            message_type => {
                NetlinkPayload::SockDiag(SockDiagMessage::parse(message_type, &self.payload())?)
            }

            #[cfg(not(any(feature = "rtnetlink", feature = "audit", feature = "sock_diag")))]
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

            #[cfg(feature = "sock_diag")]
            SockDiag(ref msg) => msg.buffer_len(),

            #[cfg(not(any(feature = "rtnetlink", feature = "audit", feature = "sock_diag")))]
            __Default => 0,
        };

        self.header.buffer_len() + payload_len
    }

    fn emit(&self, buffer: &mut [u8]) {
        use self::NetlinkPayload::*;

        self.header.emit(buffer);

        let buffer = &mut buffer[self.header.buffer_len()..self.header.length as usize];
        match self.payload {
            Noop | Done => {}
            Overrun(ref bytes) => buffer.copy_from_slice(bytes),
            Error(ref msg) => msg.emit(buffer),
            Ack(ref msg) => msg.emit(buffer),

            #[cfg(feature = "rtnetlink")]
            Rtnl(ref msg) => msg.emit(buffer),

            #[cfg(feature = "audit")]
            Audit(ref msg) => msg.emit(buffer),

            #[cfg(feature = "sock_diag")]
            SockDiag(ref msg) => msg.emit(buffer),

            #[cfg(not(any(feature = "rtnetlink", feature = "audit", feature = "sock_diag")))]
            __Default => {}
        }
    }
}

#[cfg(test)]
mod test {
    use super::{NetlinkBuffer, NetlinkMessage, Parseable};

    #[cfg(feature = "rtnetlink")]
    #[test]
    fn fuzz_bug_1() {
        let data = vec![
            0x10, 0x00, 0x00, 0x00, // length = 16
            0x40, 0x00, // message type = 64 (neighbour table message)
            0x00, 0x3d, // flags
            0x00, 0x00, // seq number
            0xe9, 0xc8, 0x50, 0x00, // port id
            0x00, 0x50, // invalid neighbour table message
        ];
        let _ = <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&NetlinkBuffer::new(&data));
    }

    #[cfg(feature = "rtnetlink")]
    #[test]
    fn fuzz_bug_2() {
        let data = vec![
            0x10, 0x00, 0x00, 0x00, // length = 16
            0x02, 0x00, // message type = 2 (error message)
            0x00, 0xc3, // flags
            0xff, 0xf7, // seq number
            0xcc, 0xc8, 0x50, 0x00, // port id
            0x00, 0x00, // invalid (error message)
        ];
        let _ = <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&NetlinkBuffer::new(&data));
    }

    #[cfg(feature = "sock_diag")]
    #[test]
    fn fuzz_bug_3() {
        let data = vec![
            0x26, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x11, 0x00, 0x00, 0xff, 0xff,
            0xff, 0x18, 0x01, 0xff, 0x00, 0x00, 0x00, 0x10, 0xff, 0x11, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x18,
            0x00, 0x1d,
        ];
        let _ = <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&NetlinkBuffer::new(&data));
    }

    #[cfg(feature = "sock_diag")]
    #[test]
    fn fuzz_bug_4() {
        let data = vec![
            0x28, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x11, 0x10, 0x00, 0x00, 0xfd, 0xdf,
            0xff, 0x18, 0x01, 0x02, 0x09, 0x11, 0x34, 0x00, 0x00, 0x01, 0x00, 0xff, 0x6e, 0x28,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x28, 0xff, 0xff, 0x14,
        ];
        let _ = <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&NetlinkBuffer::new(&data));
    }
}
