use super::*;
use constants::*;

use {
    AckMessage, Emitable, Error, ErrorBuffer, ErrorMessage, NetlinkBuffer, NetlinkHeader,
    Parseable, Result,
};

/// Represent a netlink message.
///
/// A netlink message is made of a header (represented by
/// [`NetlinkHeader`](struct.NetlinkHeader.html)) and message (represented by
/// [`RtnlMessage`](enum.RtnlMessage.html)):
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
/// |                          (variable length)                        |    |  RtnlMessage
/// |                                                                   |    |
/// |                                                                   |   /
/// +----------------+----------------+----------------+----------------+
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NetlinkMessage {
    header: NetlinkHeader,
    message: RtnlMessage,
    finalized: bool,
}

impl From<RtnlMessage> for NetlinkMessage {
    fn from(message: RtnlMessage) -> Self {
        NetlinkMessage {
            header: NetlinkHeader::default(),
            message,
            finalized: false,
        }
    }
}

impl NetlinkMessage {
    pub fn into_parts(self) -> (NetlinkHeader, RtnlMessage) {
        (self.header, self.message)
    }

    pub fn message(&self) -> &RtnlMessage {
        &self.message
    }

    pub fn message_mut(&mut self) -> &mut RtnlMessage {
        &mut self.message
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
    /// Instead, an error is returned. Note that you must call [`finalize()`](#method.finalize)
    /// before calling this method, otherwise, `Error::Malformed` is returned.
    pub fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize> {
        if !self.finalized {
            Err(Error::Malformed)
        } else if self.header().length() as usize > buffer.len() {
            Err(Error::Exhausted)
        } else {
            self.emit(buffer);
            Ok(self.header().length() as usize)
        }
    }

    /// Try to parse a message from a buffer
    pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
        NetlinkBuffer::new_checked(&buffer)?.parse()
    }

    /// Check if the payload is a `NLMSG_DONE` message
    /// ([`Rtnl::Done`](enum.RtnlMessage.html#variant.Done))
    pub fn is_done(&self) -> bool {
        self.message().is_done()
    }

    /// Check if the payload is a `NLMSG_NOOP` message
    /// ([`Rtnl::Noop`](enum.RtnlMessage.html#variant.Noop))
    pub fn is_noop(&self) -> bool {
        self.message().is_noop()
    }

    /// Check if the payload is a `NLMSG_OVERRUN` message
    /// ([`Rtnl::Overrun`](enum.RtnlMessage.html#variant.Overrun))
    pub fn is_overrun(&self) -> bool {
        self.message().is_overrun()
    }

    /// Check if the payload is a `NLMSG_ERROR` message with a negative error code
    /// ([`Rtnl::Error`](enum.RtnlMessage.html#variant.Error))
    pub fn is_error(&self) -> bool {
        self.message().is_error()
    }

    /// Check if the payload is a `NLMSG_ERROR` message with a non-negative error code
    /// ([`Rtnl::Ack`](enum.RtnlMessage.html#variant.Ack))
    pub fn is_ack(&self) -> bool {
        self.message().is_ack()
    }

    /// Check if the payload is a `RTM_NEWLINK` message
    /// ([`Rtnl::NewLink`](enum.RtnlMessage.html#variant.NewLink))
    pub fn is_new_link(&self) -> bool {
        self.message().is_new_link()
    }

    /// Check if the payload is a `RTM_DELLINK` message
    /// ([`Rtnl::DelLink`](enum.RtnlMessage.html#variant.DelLink))
    pub fn is_del_link(&self) -> bool {
        self.message().is_del_link()
    }

    /// Check if the payload is a `RTM_GETLINK` message
    /// ([`Rtnl::GetLink`](enum.RtnlMessage.html#variant.GetLink))
    pub fn is_get_link(&self) -> bool {
        self.message().is_get_link()
    }

    /// Check if the payload is a `RTM_SETLINK` message
    /// ([`Rtnl::SetLink`](enum.RtnlMessage.html#variant.SetLink))
    pub fn is_set_link(&self) -> bool {
        self.message().is_set_link()
    }

    /// Check if the payload is a `RTM_NEWADDR` message
    /// ([`Rtnl::NewAddress`](enum.RtnlMessage.html#variant.NewAddress))
    pub fn is_new_address(&self) -> bool {
        self.message().is_new_address()
    }

    /// Check if the payload is a `RTM_DELADDR` message
    /// ([`Rtnl::DelAddress`](enum.RtnlMessage.html#variant.DelAddress))
    pub fn is_del_address(&self) -> bool {
        self.message().is_del_address()
    }

    /// Check if the payload is a `RTM_GETADDR` message
    /// ([`Rtnl::GetAddress`](enum.RtnlMessage.html#variant.GetAddress))
    pub fn is_get_address(&self) -> bool {
        self.message().is_get_address()
    }

    /// Ensure the header (`NetlinkHeader`) is consistent with the payload (`RtnlMessage`):
    ///
    /// - compute the payload length and set the header's length field
    /// - check the payload type and set the header's message type field accordingly
    ///
    /// If you are not 100% sure the header is correct, this method should be called before calling
    /// [`Emitable::emit()`](trait.Emitable.html#tymethod.emit) or
    /// [`to_bytes()`](#method.to_bytes). `emit()` could panic if the header is inconsistent with
    /// the rest of the message, and `to_bytes()` would return an error.
    pub fn finalize(&mut self) {
        use self::RtnlMessage::*;
        *self.header.length_mut() = self.buffer_len() as u32;
        *self.header.message_type_mut() = match self.message {
            Noop => NLMSG_NOOP,
            Done => NLMSG_DONE,
            Error(_) | Ack(_) => NLMSG_ERROR,
            Overrun(_) => NLMSG_OVERRUN,
            NewLink(_) => RTM_NEWLINK,
            DelLink(_) => RTM_DELLINK,
            GetLink(_) => RTM_GETLINK,
            SetLink(_) => RTM_SETLINK,
            NewAddress(_) => RTM_NEWADDR,
            DelAddress(_) => RTM_DELADDR,
            GetAddress(_) => RTM_GETADDR,
            // NewRoute(_) => RTM_NEWROUTE,
            // DelRoute(_) => RTM_DELROUTE,
            // GetRoute(_) => RTM_GETROUTE,
            // NewNeighbour(_) => RTM_NEWNEIGH,
            // DelNeighbour(_) => RTM_DELNEIGH,
            // GetNeighbour(_) => RTM_GETNEIGH,
            // NewRule(_) => RTM_NEWRULE,
            // DelRule(_) => RTM_DELRULE,
            // GetRule(_) => RTM_GETRULE,
            // NewQueueDiscipline(_) => RTM_NEWQDISC,
            // DelQueueDiscipline(_) => RTM_DELQDISC,
            // GetQueueDiscipline(_) => RTM_GETQDISC,
            // NewTrafficClass(_) => RTM_NEWTCLASS,
            // DelTrafficClass(_) => RTM_DELTCLASS,
            // GetTrafficClass(_) => RTM_GETTCLASS,
            // NewTrafficFilter(_) => RTM_NEWTFILTER,
            // DelTrafficFilter(_) => RTM_DELTFILTER,
            // GetTrafficFilter(_) => RTM_GETTFILTER,
            // NewAction(_) => RTM_NEWACTION,
            // DelAction(_) => RTM_DELACTION,
            // GetAction(_) => RTM_GETACTION,
            // NewPrefix(_) => RTM_NEWPREFIX,
            // GetMulticast(_) => RTM_GETMULTICAST,
            // GetAnycast(_) => RTM_GETANYCAST,
            // NewNeighbourTable(_) => RTM_NEWNEIGHTBL,
            // SetNeighbourTable(_) => RTM_SETNEIGHTBL,
            // GetNeighbourTable(_) => RTM_GETNEIGHTBL,
            // NewNeighbourDiscoveryUserOption(_) => RTM_NEWNDUSEROPT,
            // NewAddressLabel(_) => RTM_NEWADDRLABEL,
            // DelAddressLabel(_) => RTM_DELADDRLABEL,
            // GetAddressLabel(_) => RTM_GETADDRLABEL,
            // GetDcb(_) => RTM_GETDCB,
            // SetDcb(_) => RTM_SETDCB,
            // NewNetconf(_) => RTM_NEWNETCONF,
            // DelNetconf(_) => RTM_DELNETCONF,
            // GetNetconf(_) => RTM_GETNETCONF,
            // NewMdb(_) => RTM_NEWMDB,
            // DelMdb(_) => RTM_DELMDB,
            // GetMdb(_) => RTM_GETMDB,
            // NewNsId(_) => RTM_NEWNSID,
            // DelNsId(_) => RTM_DELNSID,
            // GetNsId(_) => RTM_GETNSID,
            // NewStats(_) => RTM_NEWSTATS,
            // GetStats(_) => RTM_GETSTATS,
            // NewCacheReport(_) => RTM_NEWCACHEREPORT,
            Other(_) => unimplemented!(),
        };
        self.finalized = true;
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NetlinkMessage> for NetlinkBuffer<&'buffer T> {
    fn parse(&self) -> Result<NetlinkMessage> {
        use self::RtnlMessage::*;
        let header = <Self as Parseable<NetlinkHeader>>::parse(self)?;

        let message = match header.message_type() {
            // Link messages
            RTM_NEWLINK | RTM_GETLINK | RTM_DELLINK | RTM_SETLINK => {
                let msg: LinkMessage = LinkBuffer::new(&self.payload()).parse()?;
                match header.message_type() {
                    RTM_NEWLINK => NewLink(msg),
                    RTM_GETLINK => GetLink(msg),
                    RTM_DELLINK => DelLink(msg),
                    RTM_SETLINK => SetLink(msg),
                    _ => unreachable!(),
                }
            }

            // Address messages
            RTM_NEWADDR | RTM_GETADDR | RTM_DELADDR => {
                let msg: AddressMessage = AddressBuffer::new(&self.payload()).parse()?;
                match header.message_type() {
                    RTM_NEWADDR => NewAddress(msg),
                    RTM_GETADDR => GetAddress(msg),
                    RTM_DELADDR => DelAddress(msg),
                    _ => unreachable!(),
                }
            }

            NLMSG_ERROR => {
                let msg: ErrorMessage = ErrorBuffer::new(&self.payload()).parse()?;
                if msg.code >= 0 {
                    Ack(msg as AckMessage)
                } else {
                    Error(msg)
                }
            }
            NLMSG_NOOP => Noop,
            NLMSG_DONE => Done,
            _ => Other(self.payload().to_vec()),
        };
        Ok(NetlinkMessage {
            header,
            message,
            finalized: true,
        })
    }
}

impl Emitable for NetlinkMessage {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn buffer_len(&self) -> usize {
        use self::RtnlMessage::*;
        let payload_len = match self.message {
            Noop | Done => 0,

            | Overrun(ref bytes)
            | Other(ref bytes)
            => bytes.len(),

            Error(ref msg) => msg.buffer_len(),
            Ack(ref msg) => msg.buffer_len(),

            | NewLink(ref msg)
            | DelLink(ref msg)
            | GetLink(ref msg)
            | SetLink(ref msg)
            =>  msg.buffer_len(),

            | NewAddress(ref msg)
            | DelAddress(ref msg)
            | GetAddress(ref msg)
            => msg.buffer_len()
        };
        self.header.buffer_len() + payload_len
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit(&self, buffer: &mut [u8]) {
        use self::RtnlMessage::*;
        self.header.emit(buffer);
        let buffer = &mut buffer[self.header.buffer_len()..];
        match self.message {
            Noop | Done => {},

            Overrun(ref bytes)
            | Other(ref bytes)
            => buffer.copy_from_slice(bytes),

            Error(ref msg) => msg.emit(buffer),
            Ack(ref msg) => msg.emit(buffer),

            | NewLink(ref msg)
            | DelLink(ref msg)
            | GetLink(ref msg)
            | SetLink(ref msg)
            => msg.emit(buffer),

            | NewAddress(ref msg)
            | DelAddress(ref msg)
            | GetAddress(ref msg)
            => msg.emit(buffer)
        }
    }
}
