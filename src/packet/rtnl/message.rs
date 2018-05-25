use super::*;
use packet::common::{Emitable, Error, Parseable, Result};
use packet::constants::message_type::*;
use packet::{NetlinkBuffer, NetlinkFlags, NetlinkHeader};

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

    // fn into_raw(self) -> (NetlinkHeader, RtnlMessage) {
    //     (NetlinkHeader, RtnlLinkMessage)
    // }

    // pub fn len(&self) -> usize {
    //     self.buffer_len()
    // }

    // pub fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize> {
    //     if self.buffer_len() > buffer.len() {
    //         return Err(Error::Exhausted);
    //     }
    //     self.emit(buffer);
    //     Ok(self.buffer_len())
    // }

    // pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
    //     NetlinkBuffer::new_checked(&buffer)?.parse()
    // }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RtnlMessage {
    Done,
    Error(Vec<u8>),
    Noop,
    Overrun(Vec<u8>),
    NewLink(RtnlLinkMessage),
    DelLink(RtnlLinkMessage),
    GetLink(RtnlLinkMessage),
    SetLink(RtnlLinkMessage),
    NewAddress(RtnlAddressMessage),
    DelAddress(RtnlAddressMessage),
    GetAddress(RtnlAddressMessage),
    Other(Vec<u8>),
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NetlinkMessage> for NetlinkBuffer<&'buffer T> {
    fn parse(&self) -> Result<NetlinkMessage> {
        use self::RtnlMessage::*;
        let header = <Self as Parseable<NetlinkHeader>>::parse(self)?;

        let message = match header.message_type {
            // Link messages
            RTM_NEWLINK | RTM_GETLINK | RTM_DELLINK | RTM_SETLINK => {
                let msg: RtnlLinkMessage = RtnlLinkBuffer::new(&self.payload()).parse()?;
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
                let msg: RtnlAddressMessage = RtnlAddressBuffer::new(&self.payload()).parse()?;
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
        Ok(NetlinkMessage {
            header,
            message,
            finalized: true,
        })
    }
}

impl Emitable for NetlinkMessage {
    #[allow(unused_attributes)]
    #[rustfmt::skip]
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

    #[allow(unused_attributes)]
    #[rustfmt::skip]
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

    // Note one thing that does not really work with this is that before emitting, we usually need
    // to know how big the packet is, so we need to call buffer_len() (which does a match)
    // anyway...
    //
    // #[allow(unused_attributes)]
    // #[rustfmt::skip]
    // fn emit(&self, buffer: &mut [u8]) {
    //     use self::RtnlMessage::*;
    //     // Some weird stuff is going on here. The reason is self.header does not have the `message_type`
    //     // and `length` fields set, and we have to do it ourself. We could ask users to set these
    //     // fields, but if they forget or set wrong values, emitting will panic.
    //     //
    //     // One way to set the length and flags would be to first set the length and message type,
    //     // and then emit the payload:
    //     //
    //     // ```
    //     // self.header.length = self.buffer_len() as u32; // internally we match on self.message
    //     // self.header.message_type = match self.message {
    //     //      // pick message type
    //     // }
    //     // match self.message {
    //     //      // emit the message
    //     // }
    //     // ```
    //     //
    //     // But that is 3 big match statements, which might get expensive in a tight loop. Instead
    //     // we do everything in one big match here.
    //     //
    //     // FIXME: Is the copmlexity really worth it? Only benchmarks would tell. This may well be
    //     // premature optimization because the compiler may be able to optimize the two `match`.

    //     // First emit the header. Note that the header is incomplete: the length and flags fields
    //     // are not set to accurate values.
    //     self.header.emit(buffer);

    //     // Wrap the header buffer into a NetlinkBuffer so that we have getters and setters for each
    //     // field. Note that we cannot call `new_checked` here because it relies on the length
    //     // field and the payload. We don't have an accurate length field yet, and the storage does
    //     // not contain the payload.
    //     let mut header = NetlinkBuffer::new(buffer);

    //     match self.message {
    //         Noop => {
    //             header.set_length(self.header.buffer_len() as u32);
    //             header.set_message_type(NLMSG_NOOP);
    //         },
    //         Done => {
    //             header.set_length(self.header.buffer_len() as u32);
    //             header.set_message_type(NLMSG_DONE);
    //         }
    //         Error(ref bytes) => {
    //             header.set_length(self.header.buffer_len() as u32 + bytes.len() as u32);
    //             header.set_message_type(NLMSG_ERROR);
    //             header.payload_mut().copy_from_slice(bytes.as_slice());
    //         }
    //         Overrun(ref bytes) => {
    //             header.set_length(self.header.buffer_len() as u32 + bytes.len() as u32);
    //             header.set_message_type(NLMSG_OVERRUN);
    //             header.payload_mut().copy_from_slice(bytes.as_slice());
    //         }
    //         Other(ref bytes) => {
    //             header.set_length(self.header.buffer_len() as u32 + bytes.len() as u32);
    //             header.payload_mut().copy_from_slice(bytes.as_slice());
    //         }
    //         NewLink(ref msg) => {
    //             header.set_length(self.header.buffer_len() as u32 + msg.buffer_len() as u32);
    //             header.set_message_type(RTM_NEWLINK);
    //             msg.emit(header.payload_mut());
    //         }
    //         DelLink(ref msg) => {
    //             header.set_length(self.header.buffer_len() as u32 + msg.buffer_len() as u32);
    //             header.set_message_type(RTM_DELLINK);
    //             msg.emit(header.payload_mut());
    //         }
    //         GetLink(ref msg) => {
    //             header.set_length(self.header.buffer_len() as u32 + msg.buffer_len() as u32);
    //             header.set_message_type(RTM_GETLINK);
    //             msg.emit(header.payload_mut());
    //         }
    //         SetLink(ref msg) => {
    //             header.set_length(self.header.buffer_len() as u32 + msg.buffer_len() as u32);
    //             header.set_message_type(RTM_SETLINK);
    //             msg.emit(header.payload_mut());
    //         }
    //         NewAddress(ref msg) => {
    //             header.set_length(self.header.buffer_len() as u32 + msg.buffer_len() as u32);
    //             header.set_message_type(RTM_NEWADDR);
    //             msg.emit(header.payload_mut());
    //         }
    //         DelAddress(ref msg) => {
    //             header.set_length(self.header.buffer_len() as u32 + msg.buffer_len() as u32);
    //             header.set_message_type(RTM_DELADDR);
    //             msg.emit(header.payload_mut());
    //         }
    //         GetAddress(ref msg) => {
    //             header.set_length(self.header.buffer_len() as u32 + msg.buffer_len() as u32);
    //             header.set_message_type(RTM_GETADDR);
    //             msg.emit(header.payload_mut());
    //         }
    //     }
    // }
}
