// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32,
    DecodeError,
    Emitable,
    Parseable,
};

const MPTCP_PM_ATTR_RCV_ADD_ADDRS: u16 = 2;
const MPTCP_PM_ATTR_SUBFLOWS: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MptcpPathManagerLimitsAttr {
    RcvAddAddrs(u32),
    Subflows(u32),
    Other(DefaultNla),
}

impl Nla for MptcpPathManagerLimitsAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Other(attr) => attr.value_len(),
            _ => 4,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::RcvAddAddrs(_) => MPTCP_PM_ATTR_RCV_ADD_ADDRS,
            Self::Subflows(_) => MPTCP_PM_ATTR_SUBFLOWS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::RcvAddAddrs(d) | Self::Subflows(d) => NativeEndian::write_u32(buffer, *d),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for MptcpPathManagerLimitsAttr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MPTCP_PM_ATTR_RCV_ADD_ADDRS => Self::RcvAddAddrs(
                parse_u32(payload).context("Invalid MPTCP_PM_ATTR_RCV_ADD_ADDRS value")?,
            ),
            MPTCP_PM_ATTR_SUBFLOWS => {
                Self::Subflows(parse_u32(payload).context("Invalid MPTCP_PM_ATTR_SUBFLOWS value")?)
            }
            _ => Self::Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}
