use std::mem;

use byteorder::{ByteOrder, NativeEndian};
use try_from::TryFrom;

use crate::sock_diag::{
    buffer::{array_of, CStruct, RtaIterator, REQ_FAMILY, REQ_PROTOCOL},
    inet::INET_DIAG_NOCOOKIE,
    packet::{raw::show::*, Attribute, Info, McList, Ring},
    SkMemInfo,
};
use crate::{DecodeError, Field, Parseable, ParseableParametrized, Rest};

const REQ_INO: Field = 4..8;
const REQ_SHOW: Field = 8..12;
const REQ_COOKIE: Field = array_of::<u32>(12, 2);
const REQ_SIZE: usize = REQ_COOKIE.end;

const MSG_FAMILY: usize = 0;
const MSG_TYPE: usize = 1;
const MSG_NUM: Field = 2..4;
const MSG_INO: Field = 4..8;
const MSG_COOKIE: Field = array_of::<u32>(8, 2);
const MSG_SIZE: usize = MSG_COOKIE.end;
const MSG_ATTRIBUTES: Rest = MSG_SIZE..;

bitflags! {
    ///  This is a set of flags defining what kind of information to report.
    pub struct Show: u32 {
        /// Basic packet_sk information
        const INFO = PACKET_SHOW_INFO as u32;
        /// A set of packet_diag_mclist-s
        const MCLIST = PACKET_SHOW_MCLIST as u32;
        /// Rings configuration parameters
        const RING_CFG = PACKET_SHOW_RING_CFG as u32;
        const FANOUT = PACKET_SHOW_FANOUT as u32;
        const MEMINFO = PACKET_SHOW_MEMINFO as u32;
        const FILTER = PACKET_SHOW_FILTER as u32;
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
    pub fn num(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[MSG_NUM])
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
        if value <= Self::max_value() {
            Ok(unsafe { mem::transmute(value) })
        } else {
            Err(format!("unknown attribute: {}", value).into())
        }
    }
}

impl CStruct for Info {}
impl CStruct for Ring {}
impl CStruct for McList {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Fanout {
    pub id: u16,
    pub ty: u16,
}

impl Fanout {
    pub fn ty(&self) -> u16 {
        self.ty & 0xFF
    }
}

/// PACKET socket information
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Attr {
    Info(Info),
    McList(Vec<McList>),
    RxRing(Ring),
    TxRing(Ring),
    Fanout(Fanout),
    Uid(u32),
    MemInfo(SkMemInfo),
    Filter(Vec<u8>),
    /// other attribute
    Other(Attribute, Vec<u8>),
}

impl<T: AsRef<[u8]>> ParseableParametrized<Attr, Attribute> for T {
    fn parse_with_param(&self, ty: Attribute) -> Result<Attr, DecodeError> {
        use Attribute::*;

        let payload = self.as_ref();

        Ok(match ty {
            PACKET_DIAG_INFO if payload.len() >= mem::size_of::<Info>() => {
                Attr::Info(payload.parse()?)
            }
            PACKET_DIAG_MCLIST if payload.len() >= mem::size_of::<McList>() => Attr::McList(
                payload
                    .chunks_exact(mem::size_of::<McList>())
                    .map(|buf| buf.parse())
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            PACKET_DIAG_RX_RING if payload.len() >= mem::size_of::<Ring>() => {
                Attr::RxRing(payload.parse()?)
            }
            PACKET_DIAG_TX_RING if payload.len() >= mem::size_of::<Ring>() => {
                Attr::TxRing(payload.parse()?)
            }
            PACKET_DIAG_FANOUT if payload.len() >= mem::size_of::<u32>() => {
                let fanout = NativeEndian::read_u32(payload);

                Attr::Fanout(Fanout {
                    id: (fanout & 0xFF) as u16,
                    ty: ((fanout >> 16) & 0xFF) as u16,
                })
            }
            PACKET_DIAG_UID if payload.len() >= mem::size_of::<u32>() => {
                Attr::Uid(NativeEndian::read_u32(payload))
            }
            PACKET_DIAG_MEMINFO if payload.len() >= mem::size_of::<SkMemInfo>() => {
                Attr::MemInfo(payload.parse()?)
            }
            PACKET_DIAG_FILTER => Attr::Filter(payload.to_vec()),
            _ => Attr::Other(ty, payload.to_vec()),
        })
    }
}
