use std::mem;

use byteorder::{ByteOrder, NativeEndian};
use try_from::TryFrom;

use crate::constants::*;
use crate::sock_diag::{
    buffer::{array_of, CStruct, RtaIterator, REQ_FAMILY, REQ_PROTOCOL},
    inet::INET_DIAG_NOCOOKIE,
    netlink::{raw::*, Attribute, Ring},
    SkMemInfo,
};
use crate::{DecodeError, Field, Parseable, ParseableParametrized, Rest};

const REQ_INO: Field = 4..8;
const REQ_SHOW: Field = 8..12;
const REQ_COOKIE: Field = array_of::<u32>(12, 2);
const REQ_SIZE: usize = REQ_COOKIE.end;

const MSG_FAMILY: usize = 0;
const MSG_TYPE: usize = 1;
const MSG_PROTO: usize = 2;
const MSG_STATE: usize = 3;

const MSG_PORTID: Field = 4..8;
const MSG_DST_PORTID: Field = 8..12;
const MSG_DST_GROUP: Field = 12..16;
const MSG_INO: Field = 16..20;
const MSG_COOKIE: Field = array_of::<u32>(20, 2);
const MSG_SIZE: usize = MSG_COOKIE.end;
const MSG_ATTRIBUTES: Rest = MSG_SIZE..;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    UNCONNECTED = NETLINK_UNCONNECTED as u8,
    CONNECTED = NETLINK_CONNECTED as u8,
}

impl TryFrom<u8> for State {
    type Err = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Err> {
        match i32::from(value) {
            NETLINK_UNCONNECTED => Ok(State::UNCONNECTED),
            NETLINK_CONNECTED => Ok(State::CONNECTED),
            _ => Err(format!("unknown state: {}", value).into()),
        }
    }
}

bitflags! {
    ///  This is a set of flags defining what kind of information to report.
    pub struct Show: u32 {
        /// show memory info of a socket
        const MEMINFO = NDIAG_SHOW_MEMINFO;
        /// show groups of a netlink socket
        const GROUPS = NDIAG_SHOW_GROUPS;
        /// show ring configuration
        const RING_CFG = NDIAG_SHOW_RING_CFG;
        /// show flags of a netlink socket
        const FLAGS = NDIAG_SHOW_FLAGS;
    }
}

bitflags! {
    pub struct Flags: u32 {
        const CB_RUNNING = NDIAG_FLAG_CB_RUNNING;
        const PKTINFO = NDIAG_FLAG_PKTINFO;
        const BROADCAST_ERROR = NDIAG_FLAG_BROADCAST_ERROR;
        const NO_ENOBUFS = NDIAG_FLAG_NO_ENOBUFS;
        const LISTEN_ALL_NSID = NDIAG_FLAG_LISTEN_ALL_NSID;
        const CAP_ACK = NDIAG_FLAG_CAP_ACK;
        const EXT_ACK = NDIAG_FLAG_EXT_ACK;
        const STRICT_CHK = NDIAG_FLAG_STRICT_CHK;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestBuffer<T> {
    buffer: T,
}

impl<T> RequestBuffer<T> {
    pub fn new(buffer: T) -> RequestBuffer<T> {
        RequestBuffer { buffer }
    }

    pub const fn len() -> usize {
        REQ_SIZE
    }
}

impl<T: AsRef<[u8]>> RequestBuffer<T> {
    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[REQ_FAMILY]
    }
    pub fn protocol(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[REQ_PROTOCOL]
    }
    pub fn inode(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[REQ_INO])
    }
    pub fn show(&self) -> Show {
        let data = self.buffer.as_ref();
        Show::from_bits_truncate(NativeEndian::read_u32(&data[REQ_SHOW]))
    }
    pub fn cookie(&self) -> Option<u64> {
        let data = self.buffer.as_ref();
        let mut cookie = [0u32; 2];
        NativeEndian::read_u32_into(&data[REQ_COOKIE], &mut cookie);
        let cookie = u64::from(cookie[0]) + (u64::from(cookie[1]) << 32);

        if cookie == INET_DIAG_NOCOOKIE {
            None
        } else {
            Some(cookie)
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RequestBuffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buffer.as_mut();
        data[REQ_FAMILY] = family;
    }
    pub fn set_protocol(&mut self, protocol: u8) {
        let data = self.buffer.as_mut();
        data[REQ_PROTOCOL] = protocol
    }
    pub fn set_inode(&mut self, inode: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[REQ_INO], inode)
    }
    pub fn set_show(&mut self, show: Show) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[REQ_SHOW], show.bits())
    }
    pub fn set_cookie(&mut self, cookie: Option<u64>) {
        let data = self.buffer.as_mut();
        let cookie = cookie.unwrap_or(INET_DIAG_NOCOOKIE);
        let cookie = [cookie as u32, (cookie >> 32) as u32];
        NativeEndian::write_u32_into(&cookie[..], &mut data[REQ_COOKIE]);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ResponseBuffer<T> {
    buffer: T,
}

impl<T> ResponseBuffer<T> {
    pub fn new(buffer: T) -> ResponseBuffer<T> {
        ResponseBuffer { buffer }
    }

    pub const fn len() -> usize {
        MSG_SIZE
    }
}

impl<T: AsRef<[u8]>> ResponseBuffer<T> {
    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    fn check_len(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < MSG_SIZE {
            Err(format!(
                "buffer size is {}, whereas a rule buffer is at least {} long",
                len, MSG_SIZE
            )
            .into())
        } else {
            Ok(())
        }
    }

    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[MSG_FAMILY]
    }
    pub fn ty(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[MSG_TYPE]
    }
    pub fn protocol(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[MSG_PROTO]
    }
    pub fn state(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[MSG_STATE]
    }
    pub fn portid(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[MSG_PORTID])
    }
    pub fn dst_portid(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[MSG_DST_PORTID])
    }
    pub fn dst_group(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[MSG_DST_GROUP])
    }
    pub fn inode(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[MSG_INO])
    }
    pub fn cookie(&self) -> Option<u64> {
        let data = self.buffer.as_ref();
        let mut cookie = [0u32; 2];
        NativeEndian::read_u32_into(&data[MSG_COOKIE], &mut cookie);
        let cookie = u64::from(cookie[0]) + (u64::from(cookie[1]) << 32);

        if cookie == INET_DIAG_NOCOOKIE {
            None
        } else {
            Some(cookie)
        }
    }
    pub fn attrs(&self) -> RtaIterator<&[u8]> {
        let data = self.buffer.as_ref();
        RtaIterator::new(&data[MSG_ATTRIBUTES])
    }
}

impl TryFrom<u16> for Attribute {
    type Err = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Err> {
        if value <= Self::max_value() as u16 {
            Ok(unsafe { mem::transmute(value) })
        } else {
            Err(format!("unknown attribute: {}", value).into())
        }
    }
}

impl CStruct for Ring {}

/// PACKET socket information
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Attr {
    MemInfo(SkMemInfo),
    Groups(u32),
    RxRing(Ring),
    TxRing(Ring),
    Flags(Flags),
    Other(u16, Vec<u8>),
}

impl<T: AsRef<[u8]>> ParseableParametrized<Attr, u16> for T {
    fn parse_with_param(&self, ty: u16) -> Result<Attr, DecodeError> {
        use Attribute::*;

        let payload = self.as_ref();

        Attribute::try_from(ty)
            .and_then(|attr| {
                Ok(match attr {
                    NETLINK_DIAG_MEMINFO if payload.len() >= mem::size_of::<SkMemInfo>() => {
                        Attr::MemInfo(payload.parse()?)
                    }
                    NETLINK_DIAG_GROUPS if payload.len() >= mem::size_of::<u32>() => {
                        Attr::Groups(NativeEndian::read_u32(payload))
                    }
                    NETLINK_DIAG_RX_RING if payload.len() >= mem::size_of::<Ring>() => {
                        Attr::RxRing(payload.parse()?)
                    }
                    NETLINK_DIAG_TX_RING if payload.len() >= mem::size_of::<Ring>() => {
                        Attr::TxRing(payload.parse()?)
                    }
                    NETLINK_DIAG_FLAGS if payload.len() >= mem::size_of::<u32>() => {
                        Attr::Flags(Flags::from_bits_truncate(NativeEndian::read_u32(payload)))
                    }
                    _ => Attr::Other(ty, payload.to_vec()),
                })
            })
            .or_else(|_| Ok(Attr::Other(ty, payload.to_vec())))
    }
}
