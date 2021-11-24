// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_core::DecodeError;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16_be, parse_u32_be},
    Parseable,
};

use self::{
    hw_addr::{HwAddr, HwAddrBuffer},
    packet_hdr::{PacketHdr, PacketHdrBuffer},
    timestamp::{TimeStamp, TimeStampBuffer},
};

mod hw_addr;
mod packet_hdr;
mod timestamp;

pub const NFULA_PACKET_HDR: u16 = libc::NFULA_PACKET_HDR as u16;
pub const NFULA_MARK: u16 = libc::NFULA_MARK as u16;
pub const NFULA_TIMESTAMP: u16 = libc::NFULA_TIMESTAMP as u16;
pub const NFULA_IFINDEX_INDEV: u16 = libc::NFULA_IFINDEX_INDEV as u16;
pub const NFULA_IFINDEX_OUTDEV: u16 = libc::NFULA_IFINDEX_OUTDEV as u16;
pub const NFULA_IFINDEX_PHYSINDEV: u16 = libc::NFULA_IFINDEX_PHYSINDEV as u16;
pub const NFULA_IFINDEX_PHYSOUTDEV: u16 = libc::NFULA_IFINDEX_PHYSOUTDEV as u16;
pub const NFULA_HWADDR: u16 = libc::NFULA_HWADDR as u16;
pub const NFULA_PAYLOAD: u16 = libc::NFULA_PAYLOAD as u16;
pub const NFULA_PREFIX: u16 = libc::NFULA_PREFIX as u16;
pub const NFULA_UID: u16 = libc::NFULA_UID as u16;
pub const NFULA_SEQ: u16 = libc::NFULA_SEQ as u16;
pub const NFULA_SEQ_GLOBAL: u16 = libc::NFULA_SEQ_GLOBAL as u16;
pub const NFULA_GID: u16 = libc::NFULA_GID as u16;
pub const NFULA_HWTYPE: u16 = libc::NFULA_HWTYPE as u16;
pub const NFULA_HWHEADER: u16 = libc::NFULA_HWHEADER as u16;
pub const NFULA_HWLEN: u16 = libc::NFULA_HWLEN as u16;
pub const NFULA_CT: u16 = libc::NFULA_CT as u16;
pub const NFULA_CT_INFO: u16 = libc::NFULA_CT_INFO as u16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketNlas {
    PacketHdr(PacketHdr),
    Mark(u32),
    Timestamp(TimeStamp),
    IfIndexInDev(u32),
    IfIndexOutDev(u32),
    IfIndexPhysInDev(u32),
    IfIndexPhysOutDev(u32),
    HwAddr(HwAddr),
    Payload(Vec<u8>),
    Prefix(Vec<u8>),
    Uid(u32),
    Seq(u32),
    SeqGlobal(u32),
    Gid(u32),
    HwType(u16),
    HwHeader(Vec<u8>),
    HwHeaderLen(u16),
    // TODO: CT, CT_INFO, VLAN, L2HDR
    Other(DefaultNla),
}

impl From<PacketHdr> for PacketNlas {
    fn from(packet_hdr: PacketHdr) -> Self {
        PacketNlas::PacketHdr(packet_hdr)
    }
}

impl Nla for PacketNlas {
    fn value_len(&self) -> usize {
        match self {
            PacketNlas::PacketHdr(attr) => attr.value_len(),
            PacketNlas::Mark(_) => 4,
            PacketNlas::Timestamp(attr) => attr.value_len(),
            PacketNlas::IfIndexInDev(_) => 4,
            PacketNlas::IfIndexOutDev(_) => 4,
            PacketNlas::IfIndexPhysInDev(_) => 4,
            PacketNlas::IfIndexPhysOutDev(_) => 4,
            PacketNlas::HwAddr(attr) => attr.value_len(),
            PacketNlas::Payload(vec) => vec.len(),
            PacketNlas::Prefix(vec) => vec.len(),
            PacketNlas::Uid(_) => 4,
            PacketNlas::Seq(_) => 4,
            PacketNlas::SeqGlobal(_) => 4,
            PacketNlas::Gid(_) => 4,
            PacketNlas::HwType(_) => 2,
            PacketNlas::HwHeader(vec) => vec.len(),
            PacketNlas::HwHeaderLen(_) => 2,
            PacketNlas::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            PacketNlas::PacketHdr(attr) => attr.kind(),
            PacketNlas::Mark(_) => NFULA_MARK,
            PacketNlas::Timestamp(attr) => attr.kind(),
            PacketNlas::IfIndexInDev(_) => NFULA_IFINDEX_INDEV,
            PacketNlas::IfIndexOutDev(_) => NFULA_IFINDEX_OUTDEV,
            PacketNlas::IfIndexPhysInDev(_) => NFULA_IFINDEX_PHYSINDEV,
            PacketNlas::IfIndexPhysOutDev(_) => NFULA_IFINDEX_PHYSOUTDEV,
            PacketNlas::HwAddr(attr) => attr.kind(),
            PacketNlas::Payload(_) => NFULA_PAYLOAD,
            PacketNlas::Prefix(_) => NFULA_PREFIX,
            PacketNlas::Uid(_) => NFULA_UID,
            PacketNlas::Seq(_) => NFULA_SEQ,
            PacketNlas::SeqGlobal(_) => NFULA_SEQ_GLOBAL,
            PacketNlas::Gid(_) => NFULA_GID,
            PacketNlas::HwType(_) => NFULA_HWTYPE,
            PacketNlas::HwHeader(_) => NFULA_HWHEADER,
            PacketNlas::HwHeaderLen(_) => NFULA_HWLEN,
            PacketNlas::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            PacketNlas::PacketHdr(attr) => attr.emit_value(buffer),
            PacketNlas::Mark(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::Timestamp(attr) => attr.emit_value(buffer),
            PacketNlas::IfIndexInDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::IfIndexOutDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::IfIndexPhysInDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::IfIndexPhysOutDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::HwAddr(attr) => attr.emit_value(buffer),
            PacketNlas::Payload(vec) => buffer.copy_from_slice(vec),
            PacketNlas::Prefix(vec) => buffer.copy_from_slice(vec),
            PacketNlas::Uid(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::Seq(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::SeqGlobal(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::Gid(value) => BigEndian::write_u32(buffer, *value),
            PacketNlas::HwType(value) => BigEndian::write_u16(buffer, *value),
            PacketNlas::HwHeader(vec) => buffer.copy_from_slice(vec),
            PacketNlas::HwHeaderLen(value) => BigEndian::write_u16(buffer, *value),
            PacketNlas::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for PacketNlas {
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            NFULA_PACKET_HDR => {
                let buf = PacketHdrBuffer::new_checked(payload)?;
                PacketHdr::parse(&buf)?.into()
            }

            NFULA_MARK => PacketNlas::Mark(parse_u32_be(payload)?),
            NFULA_TIMESTAMP => {
                let buf = TimeStampBuffer::new_checked(&payload)?;
                PacketNlas::Timestamp(TimeStamp::parse(&buf)?)
            }
            NFULA_IFINDEX_INDEV => PacketNlas::IfIndexInDev(parse_u32_be(payload)?),
            NFULA_IFINDEX_OUTDEV => PacketNlas::IfIndexOutDev(parse_u32_be(payload)?),
            NFULA_IFINDEX_PHYSINDEV => PacketNlas::IfIndexPhysInDev(parse_u32_be(payload)?),
            NFULA_IFINDEX_PHYSOUTDEV => PacketNlas::IfIndexPhysOutDev(parse_u32_be(payload)?),
            NFULA_HWADDR => {
                let buf = HwAddrBuffer::new_checked(payload)?;
                PacketNlas::HwAddr(HwAddr::parse(&buf)?)
            }
            NFULA_PAYLOAD => PacketNlas::Payload(payload.to_vec()),
            NFULA_PREFIX => PacketNlas::Prefix(payload.to_vec()),
            NFULA_UID => PacketNlas::Uid(parse_u32_be(payload)?),
            NFULA_SEQ => PacketNlas::Seq(parse_u32_be(payload)?),
            NFULA_SEQ_GLOBAL => PacketNlas::SeqGlobal(parse_u32_be(payload)?),
            NFULA_GID => PacketNlas::Gid(parse_u32_be(payload)?),
            NFULA_HWTYPE => PacketNlas::HwType(parse_u16_be(payload)?),
            NFULA_HWHEADER => PacketNlas::HwHeader(payload.to_vec()),
            NFULA_HWLEN => PacketNlas::HwHeaderLen(parse_u16_be(payload)?),

            _ => PacketNlas::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
