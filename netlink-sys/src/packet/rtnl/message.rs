use super::*;
use constants::*;

use {Emitable, Error, NetlinkBuffer, NetlinkFlags, NetlinkHeader, Parseable, Result};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Message {
    header: NetlinkHeader,
    message: RtnlMessage,
    finalized: bool,
}

impl From<RtnlMessage> for Message {
    fn from(message: RtnlMessage) -> Self {
        Message {
            header: NetlinkHeader::default(),
            message,
            finalized: false,
        }
    }
}

impl Message {
    pub fn into_parts(self) -> (NetlinkHeader, RtnlMessage) {
        (self.header, self.message)
    }

    pub fn message(&self) -> &RtnlMessage {
        &self.message
    }
    pub fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize> {
        if !self.finalized {
            Err(Error::Malformed)
        } else if self.length() as usize > buffer.len() {
            Err(Error::Exhausted)
        } else {
            self.emit(buffer);
            Ok(self.length() as usize)
        }
    }

    pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
        NetlinkBuffer::new_checked(&buffer)?.parse()
    }

    pub fn length(&self) -> u32 {
        self.header.length
    }

    pub fn set_length(&mut self, value: u32) {
        self.header.length = value;
    }

    pub fn message_type(&self) -> u16 {
        self.header.message_type
    }

    pub fn is_done(&self) -> bool {
        self.message().is_done()
    }

    pub fn is_noop(&self) -> bool {
        self.message().is_noop()
    }

    pub fn is_overrun(&self) -> bool {
        self.message().is_overrun()
    }

    pub fn is_error(&self) -> bool {
        self.message().is_error()
    }

    pub fn is_new_link(&self) -> bool {
        self.message().is_new_link()
    }

    pub fn is_del_link(&self) -> bool {
        self.message().is_del_link()
    }

    pub fn is_get_link(&self) -> bool {
        self.message().is_get_link()
    }

    pub fn is_set_link(&self) -> bool {
        self.message().is_set_link()
    }

    pub fn is_new_address(&self) -> bool {
        self.message().is_new_address()
    }

    pub fn is_del_address(&self) -> bool {
        self.message().is_del_address()
    }

    pub fn is_get_address(&self) -> bool {
        self.message().is_get_address()
    }

    pub fn set_message_type(&mut self, value: u16) {
        self.header.message_type = value;
    }

    pub fn sequence_number(&self) -> u32 {
        self.header.sequence_number
    }

    pub fn set_sequence_number(&mut self, value: u32) {
        self.header.sequence_number = value;
    }

    pub fn flags(&self) -> NetlinkFlags {
        self.header.flags
    }

    pub fn set_flags(&mut self, flags: NetlinkFlags) {
        self.header.flags = flags;
    }

    pub fn finalize(&mut self) {
        use self::RtnlMessage::*;
        self.header.length = self.buffer_len() as u32;
        self.header.message_type = match self.message {
            Noop => NLMSG_NOOP,
            Done => NLMSG_DONE,
            Error(_) => NLMSG_ERROR,
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RtnlMessage {
    Done,
    Error(Vec<u8>),
    Noop,
    Overrun(Vec<u8>),
    NewLink(LinkMessage),
    DelLink(LinkMessage),
    GetLink(LinkMessage),
    SetLink(LinkMessage),
    NewAddress(AddressMessage),
    DelAddress(AddressMessage),
    GetAddress(AddressMessage),
    Other(Vec<u8>),
}

impl RtnlMessage {
    pub fn is_done(&self) -> bool {
        *self == RtnlMessage::Done
    }

    pub fn is_noop(&self) -> bool {
        *self == RtnlMessage::Noop
    }

    pub fn is_overrun(&self) -> bool {
        if let RtnlMessage::Overrun(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_error(&self) -> bool {
        if let RtnlMessage::Error(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_link(&self) -> bool {
        if let RtnlMessage::NewLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_link(&self) -> bool {
        if let RtnlMessage::DelLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_link(&self) -> bool {
        if let RtnlMessage::GetLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_set_link(&self) -> bool {
        if let RtnlMessage::SetLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_address(&self) -> bool {
        if let RtnlMessage::NewAddress(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_address(&self) -> bool {
        if let RtnlMessage::DelAddress(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_address(&self) -> bool {
        if let RtnlMessage::GetAddress(_) = *self {
            true
        } else {
            false
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Message> for NetlinkBuffer<&'buffer T> {
    fn parse(&self) -> Result<Message> {
        use self::RtnlMessage::*;
        let header = <Self as Parseable<NetlinkHeader>>::parse(self)?;

        let message = match header.message_type {
            // Link messages
            RTM_NEWLINK | RTM_GETLINK | RTM_DELLINK | RTM_SETLINK => {
                let msg: LinkMessage = LinkBuffer::new(&self.payload()).parse()?;
                match header.message_type {
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
                match header.message_type {
                    RTM_NEWADDR => NewAddress(msg),
                    RTM_GETADDR => GetAddress(msg),
                    RTM_DELADDR => DelAddress(msg),
                    _ => unreachable!(),
                }
            }

            NLMSG_ERROR => Error(self.payload().to_vec()),
            NLMSG_NOOP => Noop,
            NLMSG_DONE => Done,
            _ => Other(self.payload().to_vec()),
        };
        Ok(Message {
            header,
            message,
            finalized: true,
        })
    }
}

impl Emitable for Message {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn buffer_len(&self) -> usize {
        use self::RtnlMessage::*;
        let payload_len = match self.message {
            Noop | Done => 0,

            | Error(ref bytes)
            | Overrun(ref bytes)
            | Other(ref bytes)
            => bytes.len(),

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

            | Error(ref bytes)
            | Overrun(ref bytes)
            | Other(ref bytes)
            => buffer.copy_from_slice(bytes),

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
