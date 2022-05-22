// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_i32, parse_ip, parse_u16, parse_u32, parse_u8},
    DecodeError,
    Emitable,
    Parseable,
};

const MPTCP_PM_ADDR_ATTR_FAMILY: u16 = 1;
const MPTCP_PM_ADDR_ATTR_ID: u16 = 2;
const MPTCP_PM_ADDR_ATTR_ADDR4: u16 = 3;
const MPTCP_PM_ADDR_ATTR_ADDR6: u16 = 4;
const MPTCP_PM_ADDR_ATTR_PORT: u16 = 5;
const MPTCP_PM_ADDR_ATTR_FLAGS: u16 = 6;
const MPTCP_PM_ADDR_ATTR_IF_IDX: u16 = 7;

const MPTCP_PM_ADDR_FLAG_SIGNAL: u32 = 1 << 0;
const MPTCP_PM_ADDR_FLAG_SUBFLOW: u32 = 1 << 1;
const MPTCP_PM_ADDR_FLAG_BACKUP: u32 = 1 << 2;
const MPTCP_PM_ADDR_FLAG_FULLMESH: u32 = 1 << 3;
const MPTCP_PM_ADDR_FLAG_IMPLICIT: u32 = 1 << 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MptcpPathManagerAddressAttrFlag {
    Signal,
    Subflow,
    Backup,
    Fullmesh,
    Implicit,
    Other(u32),
}

fn u32_to_vec_flags(value: u32) -> Vec<MptcpPathManagerAddressAttrFlag> {
    let mut ret = Vec::new();
    let mut found = 0u32;
    if (value & MPTCP_PM_ADDR_FLAG_SIGNAL) > 0 {
        found += MPTCP_PM_ADDR_FLAG_SIGNAL;
        ret.push(MptcpPathManagerAddressAttrFlag::Signal);
    }
    if (value & MPTCP_PM_ADDR_FLAG_SUBFLOW) > 0 {
        found += MPTCP_PM_ADDR_FLAG_SUBFLOW;
        ret.push(MptcpPathManagerAddressAttrFlag::Subflow);
    }
    if (value & MPTCP_PM_ADDR_FLAG_BACKUP) > 0 {
        found += MPTCP_PM_ADDR_FLAG_BACKUP;
        ret.push(MptcpPathManagerAddressAttrFlag::Backup);
    }
    if (value & MPTCP_PM_ADDR_FLAG_FULLMESH) > 0 {
        found += MPTCP_PM_ADDR_FLAG_FULLMESH;
        ret.push(MptcpPathManagerAddressAttrFlag::Fullmesh);
    }
    if (value & MPTCP_PM_ADDR_FLAG_IMPLICIT) > 0 {
        found += MPTCP_PM_ADDR_FLAG_IMPLICIT;
        ret.push(MptcpPathManagerAddressAttrFlag::Implicit);
    }
    if (value - found) > 0 {
        ret.push(MptcpPathManagerAddressAttrFlag::Other(value - found));
    }
    ret
}

impl From<&MptcpPathManagerAddressAttrFlag> for u32 {
    fn from(v: &MptcpPathManagerAddressAttrFlag) -> u32 {
        match v {
            MptcpPathManagerAddressAttrFlag::Signal => MPTCP_PM_ADDR_FLAG_SIGNAL,
            MptcpPathManagerAddressAttrFlag::Subflow => MPTCP_PM_ADDR_FLAG_SUBFLOW,
            MptcpPathManagerAddressAttrFlag::Backup => MPTCP_PM_ADDR_FLAG_BACKUP,
            MptcpPathManagerAddressAttrFlag::Fullmesh => MPTCP_PM_ADDR_FLAG_FULLMESH,
            MptcpPathManagerAddressAttrFlag::Implicit => MPTCP_PM_ADDR_FLAG_IMPLICIT,
            MptcpPathManagerAddressAttrFlag::Other(d) => *d,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MptcpPathManagerAddressAttr {
    Family(u16),
    Id(u8),
    Addr4(Ipv4Addr),
    Addr6(Ipv6Addr),
    Port(u16),
    Flags(Vec<MptcpPathManagerAddressAttrFlag>),
    IfIndex(i32),
    Other(DefaultNla),
}

impl Nla for MptcpPathManagerAddressAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Family(_) | Self::Port(_) => 2,
            Self::Addr4(_) | Self::Flags(_) | Self::IfIndex(_) => 4,
            Self::Id(_) => 1,
            Self::Addr6(_) => 16,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Family(_) => MPTCP_PM_ADDR_ATTR_FAMILY,
            Self::Id(_) => MPTCP_PM_ADDR_ATTR_ID,
            Self::Addr4(_) => MPTCP_PM_ADDR_ATTR_ADDR4,
            Self::Addr6(_) => MPTCP_PM_ADDR_ATTR_ADDR6,
            Self::Port(_) => MPTCP_PM_ADDR_ATTR_PORT,
            Self::Flags(_) => MPTCP_PM_ADDR_ATTR_FLAGS,
            Self::IfIndex(_) => MPTCP_PM_ADDR_ATTR_IF_IDX,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Family(d) | Self::Port(d) => NativeEndian::write_u16(buffer, *d),
            Self::Addr4(i) => buffer.copy_from_slice(&i.octets()),
            Self::Addr6(i) => buffer.copy_from_slice(&i.octets()),
            Self::Id(d) => buffer[0] = *d,
            Self::Flags(flags) => {
                let mut value = 0u32;
                for flag in flags {
                    value += u32::from(flag);
                }
                NativeEndian::write_u32(buffer, value)
            }
            Self::IfIndex(d) => NativeEndian::write_i32(buffer, *d),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for MptcpPathManagerAddressAttr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MPTCP_PM_ADDR_ATTR_FAMILY => {
                let err_msg = format!("Invalid MPTCP_PM_ADDR_ATTR_FAMILY value {:?}", payload);
                Self::Family(parse_u16(payload).context(err_msg)?)
            }
            MPTCP_PM_ADDR_ATTR_ID => {
                Self::Id(parse_u8(payload).context("Invalid MPTCP_PM_ADDR_ATTR_ID value")?)
            }
            MPTCP_PM_ADDR_ATTR_ADDR4 | MPTCP_PM_ADDR_ATTR_ADDR6 => {
                match parse_ip(payload)
                    .context("Invalid MPTCP_PM_ADDR_ATTR_ADDR4/MPTCP_PM_ADDR_ATTR_ADDR6 value")?
                {
                    IpAddr::V4(i) => Self::Addr4(i),
                    IpAddr::V6(i) => Self::Addr6(i),
                }
            }
            MPTCP_PM_ADDR_ATTR_PORT => {
                Self::Port(parse_u16(payload).context("Invalid MPTCP_PM_ADDR_ATTR_PORT value")?)
            }
            MPTCP_PM_ADDR_ATTR_FLAGS => Self::Flags(u32_to_vec_flags(
                parse_u32(payload).context("Invalid MPTCP_PM_ADDR_ATTR_FLAGS value")?,
            )),
            MPTCP_PM_ADDR_ATTR_IF_IDX => Self::IfIndex(
                parse_i32(payload).context("Invalid MPTCP_PM_ADDR_ATTR_IF_IDX value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}
