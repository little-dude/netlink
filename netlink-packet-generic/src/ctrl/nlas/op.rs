use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::mem::size_of_val;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpAttrs {
    Unspec(Vec<u8>),
    Id(u32),
    Flags(u32),
    Other(DefaultNla),
}

impl Nla for OpAttrs {
    fn value_len(&self) -> usize {
        use OpAttrs::*;
        match self {
            Unspec(bytes) => bytes.len(),
            Id(v) => size_of_val(v),
            Flags(v) => size_of_val(v),
            Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use OpAttrs::*;
        match self {
            Unspec(_) => CTRL_ATTR_OP_UNSPEC,
            Id(_) => CTRL_ATTR_OP_ID,
            Flags(_) => CTRL_ATTR_OP_FLAGS,
            Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use OpAttrs::*;
        match self {
            Unspec(bytes) => buffer.copy_from_slice(bytes),
            Id(v) => NativeEndian::write_u32(buffer, *v),
            Flags(v) => NativeEndian::write_u32(buffer, *v),
            Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for OpAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_OP_UNSPEC => Self::Unspec(payload.to_vec()),
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
