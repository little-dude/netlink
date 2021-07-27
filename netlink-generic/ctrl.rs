use std::ffi::CString;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{self, DefaultNla, NlaBuffer, NlasIterator},
    parsers::{parse_string, parse_u16, parse_u32},
    DecodeError,
    Emitable,
    Parseable,
};

const GENL_NAMSIZ: usize = 16;

const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_VERSION: u16 = 3;
const CTRL_ATTR_HDRSIZE: u16 = 4;
const CTRL_ATTR_MAXATTR: u16 = 5;
const CTRL_ATTR_OPS: u16 = 6;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;

const CTRL_ATTR_OP_ID: u16 = 1;
const CTRL_ATTR_OP_FLAGS: u16 = 2;

const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
// for kernel `struct genl_ops`
pub enum GenericNetlinkOp {
    Id(u32),
    Flags(u32),
    Other(DefaultNla),
}

impl nla::Nla for GenericNetlinkOp {
    fn value_len(&self) -> usize {
        match self {
            Self::Id(_) | Self::Flags(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => CTRL_ATTR_OP_ID,
            Self::Flags(_) => CTRL_ATTR_OP_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Id(value) | Self::Flags(value) => NativeEndian::write_u32(buffer, *value),
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for GenericNetlinkOp {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_OP_ID => {
                Self::Id(parse_u32(payload).context("invalid CTRL_ATTR_OP_ID value")?)
            }
            CTRL_ATTR_OP_FLAGS => {
                Self::Flags(parse_u32(payload).context("invalid CTRL_ATTR_OP_FLAGS value")?)
            }
            _ => Self::Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
// for kernel `struct genl_multicast_group`
pub enum GenericNetlinkMulticastGroup {
    Id(u32),
    Name(String),
    Other(DefaultNla),
}

impl nla::Nla for GenericNetlinkMulticastGroup {
    fn value_len(&self) -> usize {
        match self {
            Self::Id(_) => 4,
            Self::Name(_) => GENL_NAMSIZ,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => CTRL_ATTR_MCAST_GRP_ID,
            Self::Name(_) => CTRL_ATTR_MCAST_GRP_NAME,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Id(value) => NativeEndian::write_u32(buffer, *value),
            Self::Name(value) => str_to_zero_ended_u8_array(value, buffer, GENL_NAMSIZ),
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for GenericNetlinkMulticastGroup {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_MCAST_GRP_NAME => {
                Self::Name(parse_string(payload).context("invalid CTRL_ATTR_MCAST_GRP_NAME value")?)
            }
            CTRL_ATTR_MCAST_GRP_ID => {
                Self::Id(parse_u32(payload).context("invalid CTRL_ATTR_MCAST_GRP_ID value")?)
            }
            _ => Self::Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CtrlAttr {
    FamilyId(u16),
    FamilyName(String),
    Version(u32),
    HeaderSize(u32),
    MaxAttr(u32),
    Ops(Vec<Vec<GenericNetlinkOp>>),
    MulticastGroups(Vec<Vec<GenericNetlinkMulticastGroup>>),
    Other(DefaultNla),
}

impl nla::Nla for CtrlAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::FamilyId(_) => 2,
            Self::FamilyName(s) => {
                if s.len() > GENL_NAMSIZ - 1 {
                    GENL_NAMSIZ
                } else {
                    s.len() + 1
                }
            }
            Self::Version(_) | Self::HeaderSize(_) | Self::MaxAttr(_) => 4,
            Self::Ops(ref ops) => {
                let mut len = 0;
                for op in ops {
                    len += op.as_slice().buffer_len()
                }
                len
            }
            Self::MulticastGroups(ref groups) => {
                let mut len = 0;
                for group in groups {
                    len += group.as_slice().buffer_len()
                }
                len
            }
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::FamilyId(_) => CTRL_ATTR_FAMILY_ID,
            Self::FamilyName(_) => CTRL_ATTR_FAMILY_NAME,
            Self::Version(_) => CTRL_ATTR_VERSION,
            Self::HeaderSize(_) => CTRL_ATTR_HDRSIZE,
            Self::MaxAttr(_) => CTRL_ATTR_MAXATTR,
            Self::Ops(_) => CTRL_ATTR_OPS,
            Self::MulticastGroups(_) => CTRL_ATTR_MCAST_GROUPS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::FamilyId(value) => NativeEndian::write_u16(buffer, *value),
            Self::FamilyName(value) => str_to_zero_ended_u8_array(value, buffer, GENL_NAMSIZ),
            Self::Version(value) | Self::HeaderSize(value) | Self::MaxAttr(value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            Self::Ops(ref ops) => {
                let mut len = 0;
                for op in ops {
                    op.as_slice().emit(&mut buffer[len..]);
                    len += op.as_slice().buffer_len();
                }
            }
            Self::MulticastGroups(ref groups) => {
                let mut len = 0;
                for group in groups {
                    group.as_slice().emit(&mut buffer[len..]);
                    len += group.as_slice().buffer_len();
                }
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for CtrlAttr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_FAMILY_ID => {
                Self::FamilyId(parse_u16(payload).context("invalid CTRL_ATTR_FAMILY_ID value")?)
            }
            CTRL_ATTR_FAMILY_NAME => Self::FamilyName(
                parse_string(payload).context("invalid CTRL_ATTR_FAMILY_NAME value")?,
            ),
            CTRL_ATTR_VERSION => {
                Self::Version(parse_u32(payload).context("invalid CTRL_ATTR_VERSION value")?)
            }
            CTRL_ATTR_HDRSIZE => {
                Self::HeaderSize(parse_u32(payload).context("invalid CTRL_ATTR_HDRSIZE value")?)
            }
            CTRL_ATTR_MAXATTR => {
                Self::MaxAttr(parse_u32(payload).context("invalid CTRL_ATTR_MAXATTR value")?)
            }
            CTRL_ATTR_OPS => {
                let mut ops = Vec::new();
                let error_msg = "failed to parse CTRL_ATTR_OPS";
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    let mut op = Vec::new();
                    for nla in NlasIterator::new(nlas.value()) {
                        let nla = &nla.context(error_msg)?;
                        let parsed = GenericNetlinkOp::parse(nla).context(error_msg)?;
                        op.push(parsed);
                    }
                    ops.push(op);
                }
                Self::Ops(ops)
            }
            CTRL_ATTR_MCAST_GROUPS => {
                let mut groups = Vec::new();
                let error_msg = "failed to parse CTRL_ATTR_MCAST_GROUPS";
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    let mut group = Vec::new();
                    for nla in NlasIterator::new(nlas.value()) {
                        let nla = &nla.context(error_msg)?;
                        let parsed = GenericNetlinkMulticastGroup::parse(nla).context(error_msg)?;
                        group.push(parsed);
                    }
                    groups.push(group);
                }
                Self::MulticastGroups(groups)
            }
            _ => Self::Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}

fn str_to_zero_ended_u8_array(src_str: &str, buffer: &mut [u8], max_size: usize) {
    if let Ok(src_cstring) = CString::new(src_str.as_bytes()) {
        let src_null_ended_str = src_cstring.into_bytes_with_nul();
        if src_null_ended_str.len() > max_size {
            buffer[..max_size].clone_from_slice(&src_null_ended_str[..max_size])
        } else {
            buffer[..src_null_ended_str.len()].clone_from_slice(&src_null_ended_str)
        }
    }
}
