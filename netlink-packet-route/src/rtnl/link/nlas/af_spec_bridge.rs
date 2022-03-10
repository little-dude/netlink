// SPDX-License-Identifier: MIT
use anyhow::Context;

use crate::{
    constants::*,
    nlas::{self, DefaultNla, NlaBuffer},
    parsers::parse_u16,
    traits::Parseable,
    DecodeError,
};

use byteorder::{ByteOrder, NativeEndian};

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AfSpecBridge {
    Flags(u16),
    VlanInfo(Vec<u8>),
    Other(DefaultNla),
}

impl nlas::Nla for AfSpecBridge {
    fn value_len(&self) -> usize {
        use self::AfSpecBridge::*;
        match *self {
            VlanInfo(ref bytes) => bytes.len(),
            Flags(_) => 2,
            Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::AfSpecBridge::*;
        match *self {
            Flags(value) => NativeEndian::write_u16(buffer, value),
            VlanInfo(ref bytes) => {
                (&mut buffer[..bytes.len()]).copy_from_slice(bytes.as_slice());
            }
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::AfSpecBridge::*;
        match *self {
            Flags(_) => IFLA_BRIDGE_FLAGS,
            VlanInfo(_) => IFLA_BRIDGE_VLAN_INFO,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for AfSpecBridge {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::AfSpecBridge::*;

        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BRIDGE_VLAN_INFO => VlanInfo(payload.to_vec()),
            IFLA_BRIDGE_FLAGS => {
                Flags(parse_u16(payload).context("invalid IFLA_BRIDGE_FLAGS value")?)
            }
            kind => Other(DefaultNla::parse(buf).context(format!("Unknown NLA type {}", kind))?),
        })
    }
}
