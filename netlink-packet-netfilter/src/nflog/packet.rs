// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{BigEndian, ByteOrder};
use derive_more::{From, IsVariant};
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

#[derive(Clone, Debug, PartialEq, Eq, From, IsVariant)]
pub enum PacketNla {
    #[from]
    PacketHdr(PacketHdr),
    Mark(u32),
    #[from]
    Timestamp(TimeStamp),
    IfIndexInDev(u32),
    IfIndexOutDev(u32),
    IfIndexPhysInDev(u32),
    IfIndexPhysOutDev(u32),
    #[from]
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
    #[from]
    Other(DefaultNla),
}

impl Nla for PacketNla {
    fn value_len(&self) -> usize {
        match self {
            PacketNla::PacketHdr(attr) => attr.value_len(),
            PacketNla::Mark(_) => 4,
            PacketNla::Timestamp(attr) => attr.value_len(),
            PacketNla::IfIndexInDev(_) => 4,
            PacketNla::IfIndexOutDev(_) => 4,
            PacketNla::IfIndexPhysInDev(_) => 4,
            PacketNla::IfIndexPhysOutDev(_) => 4,
            PacketNla::HwAddr(attr) => attr.value_len(),
            PacketNla::Payload(vec) => vec.len(),
            PacketNla::Prefix(vec) => vec.len(),
            PacketNla::Uid(_) => 4,
            PacketNla::Seq(_) => 4,
            PacketNla::SeqGlobal(_) => 4,
            PacketNla::Gid(_) => 4,
            PacketNla::HwType(_) => 2,
            PacketNla::HwHeader(vec) => vec.len(),
            PacketNla::HwHeaderLen(_) => 2,
            PacketNla::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            PacketNla::PacketHdr(attr) => attr.kind(),
            PacketNla::Mark(_) => NFULA_MARK,
            PacketNla::Timestamp(attr) => attr.kind(),
            PacketNla::IfIndexInDev(_) => NFULA_IFINDEX_INDEV,
            PacketNla::IfIndexOutDev(_) => NFULA_IFINDEX_OUTDEV,
            PacketNla::IfIndexPhysInDev(_) => NFULA_IFINDEX_PHYSINDEV,
            PacketNla::IfIndexPhysOutDev(_) => NFULA_IFINDEX_PHYSOUTDEV,
            PacketNla::HwAddr(attr) => attr.kind(),
            PacketNla::Payload(_) => NFULA_PAYLOAD,
            PacketNla::Prefix(_) => NFULA_PREFIX,
            PacketNla::Uid(_) => NFULA_UID,
            PacketNla::Seq(_) => NFULA_SEQ,
            PacketNla::SeqGlobal(_) => NFULA_SEQ_GLOBAL,
            PacketNla::Gid(_) => NFULA_GID,
            PacketNla::HwType(_) => NFULA_HWTYPE,
            PacketNla::HwHeader(_) => NFULA_HWHEADER,
            PacketNla::HwHeaderLen(_) => NFULA_HWLEN,
            PacketNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            PacketNla::PacketHdr(attr) => attr.emit_value(buffer),
            PacketNla::Mark(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::Timestamp(attr) => attr.emit_value(buffer),
            PacketNla::IfIndexInDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::IfIndexOutDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::IfIndexPhysInDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::IfIndexPhysOutDev(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::HwAddr(attr) => attr.emit_value(buffer),
            PacketNla::Payload(vec) => buffer.copy_from_slice(vec),
            PacketNla::Prefix(vec) => buffer.copy_from_slice(vec),
            PacketNla::Uid(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::Seq(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::SeqGlobal(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::Gid(value) => BigEndian::write_u32(buffer, *value),
            PacketNla::HwType(value) => BigEndian::write_u16(buffer, *value),
            PacketNla::HwHeader(vec) => buffer.copy_from_slice(vec),
            PacketNla::HwHeaderLen(value) => BigEndian::write_u16(buffer, *value),
            PacketNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for PacketNla {
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            NFULA_PACKET_HDR => {
                let buf = PacketHdrBuffer::new_checked(payload)
                    .context("invalid NFULA_PACKET_HDR value")?;
                PacketHdr::parse(&buf)?.into()
            }

            NFULA_MARK => {
                PacketNla::Mark(parse_u32_be(payload).context("invalid NFULA_MARK value")?)
            }
            NFULA_TIMESTAMP => {
                let buf = TimeStampBuffer::new_checked(&payload)
                    .context("invalid NFULA_TIMESTAMP value")?;
                PacketNla::Timestamp(TimeStamp::parse(&buf)?)
            }
            NFULA_IFINDEX_INDEV => PacketNla::IfIndexInDev(
                parse_u32_be(payload).context("invalid NFULA_IFINDEX_INDEV value")?,
            ),
            NFULA_IFINDEX_OUTDEV => PacketNla::IfIndexOutDev(
                parse_u32_be(payload).context("invalid NFULA_IFINDEX_OUTDEV value")?,
            ),
            NFULA_IFINDEX_PHYSINDEV => PacketNla::IfIndexPhysInDev(
                parse_u32_be(payload).context("invalid NFULA_IFINDEX_PHYSINDEV value")?,
            ),
            NFULA_IFINDEX_PHYSOUTDEV => PacketNla::IfIndexPhysOutDev(
                parse_u32_be(payload).context("invalid NFULA_IFINDEX_PHYSOUTDEV value")?,
            ),
            NFULA_HWADDR => {
                let buf =
                    HwAddrBuffer::new_checked(payload).context("invalid NFULA_HWADDR value")?;
                PacketNla::HwAddr(HwAddr::parse(&buf)?)
            }
            NFULA_PAYLOAD => PacketNla::Payload(payload.to_vec()),
            NFULA_PREFIX => PacketNla::Prefix(payload.to_vec()),
            NFULA_UID => PacketNla::Uid(parse_u32_be(payload).context("invalid NFULA_UID value")?),
            NFULA_SEQ => PacketNla::Seq(parse_u32_be(payload).context("invalid NFULA_SEQ value")?),
            NFULA_SEQ_GLOBAL => PacketNla::SeqGlobal(
                parse_u32_be(payload).context("invalid NFULA_SEQ_GLOBAL value")?,
            ),
            NFULA_GID => PacketNla::Gid(parse_u32_be(payload).context("invalid NFULA_GID value")?),
            NFULA_HWTYPE => {
                PacketNla::HwType(parse_u16_be(payload).context("invalid NFULA_HWTYPE value")?)
            }
            NFULA_HWHEADER => PacketNla::HwHeader(payload.to_vec()),
            NFULA_HWLEN => {
                PacketNla::HwHeaderLen(parse_u16_be(payload).context("invalid NFULA_HWLEN value")?)
            }

            _ => PacketNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
