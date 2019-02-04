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

            #[cfg(not(any(feature = "rtnetlink", feature = "audit")))]
            __Default => {}
        }
    }
}

#[cfg(test)]
mod test {
    use super::{NetlinkBuffer, NetlinkMessage, Parseable};

    #[test]
    fn fuzz_bug_1() {
        let data = vec![
            0x10, 0x00, 0x00, 0x00, // length = 16
            0x40, 0x00, // message type = 64 (neighbour table message)
            0x00, 0x3d, // flags
            0x00, 0x00, // seq number
            0xe9, 0xc8, 0x50, 0x00, // port id
            0x0, 0x50, // invalid neighbour table message
        ];
        let _ = <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&NetlinkBuffer::new(&data));
    }

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

    // This test was added because one of the NLA's payload is a string that is not null
    // terminated. I'm not sure if we missed something in the IFLA_LINK_INFO spec, or if
    // linux/iproute2 is being a bit inconsistent here.
    //
    // This message was created using `ip link add qemu-br1 type bridge`.
    #[rustfmt::skip]
    #[cfg(feature = "rtnetlink")]
    #[test]
    fn test_non_null_terminated_string() {
        use crate::*;
        let data = vec![
            0x40, 0x00, 0x00, 0x00, // length = 64
            0x10, 0x00, // message type = 16 = (create network interface)
            0x05, 0x06, // flags
            0x81, 0x74, 0x57, 0x5c, // seq id
            0x00, 0x00, 0x00, 0x00, // pid
            0x00, // interface family
            0x00, // padding
            0x00, 0x00, // device type (NET/ROM pseudo)
            0x00, 0x00, 0x00, 0x00, // interface index
            0x00, 0x00, 0x00, 0x00, // device flags
            0x00, 0x00, 0x00, 0x00, // device change flags
            // NLA: device name
            0x0d, 0x00, // length = 13
            0x03, 0x00, // type = 3
            // value=qemu-br1 NOTE THAT THIS IS NULL-TERMINATED
            0x71, 0x65, 0x6d, 0x75, 0x2d, 0x62, 0x72, 0x31, 0x00,
            0x00, 0x00, 0x00, // padding
            // NLA: Link info
            0x10, 0x00, // length = 16
            0x12, 0x00, // type = link info
                // nested NLA:
                0x0a, 0x00, // length = 10
                0x01, 0x00, // type = 1 = IFLA_INFO_KIND
                // "bridge" NOTE THAT THIS IS NOT NULL-TERMINATED!
                0x62, 0x72, 0x69, 0x64, 0x67, 0x65,
                0x00, 0x00, // padding
        ];
        let expected = NetlinkMessage {
            header: NetlinkHeader {
                length: 64,
                message_type: 16,
                flags: NetlinkFlags::from(0x0605),
                sequence_number: 1549235329,
                port_number: 0,
            },
            payload: NetlinkPayload::Rtnl(RtnlMessage::NewLink(LinkMessage {
                header: LinkHeader {
                    interface_family: 0,
                    index: 0,
                    link_layer_type: LinkLayerType::Netrom,
                    flags: LinkFlags(0),
                    change_mask: LinkFlags(0),
                },
                nlas: vec![
                    LinkNla::IfName(String::from("qemu-br1")),
                    LinkNla::LinkInfo(vec![LinkInfo::Kind(LinkInfoKind::Bridge)]),
                ],
            })),
        };
        let actual =
            <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&NetlinkBuffer::new(&data))
                .unwrap();
        assert_eq!(expected, actual);
    }
}
