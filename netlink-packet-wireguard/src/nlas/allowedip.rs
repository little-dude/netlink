use crate::{
    constants::*,
    raw::{emit_ip, parse_ip, IPV4_LEN, IPV6_LEN},
};

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::{mem::size_of_val, net::IpAddr};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WgAllowedIpAttrs {
    Unspec(Vec<u8>),
    Family(u16),
    IpAddr(IpAddr),
    Cidr(u8),
}

impl Nla for WgAllowedIpAttrs {
    fn value_len(&self) -> usize {
        match self {
            WgAllowedIpAttrs::Unspec(bytes) => bytes.len(),
            WgAllowedIpAttrs::Family(v) => size_of_val(v),
            WgAllowedIpAttrs::IpAddr(v) => match *v {
                IpAddr::V4(_) => IPV4_LEN,
                IpAddr::V6(_) => IPV6_LEN,
            },
            WgAllowedIpAttrs::Cidr(v) => size_of_val(v),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            WgAllowedIpAttrs::Unspec(_) => WGALLOWEDIP_A_UNSPEC,
            WgAllowedIpAttrs::Family(_) => WGALLOWEDIP_A_FAMILY,
            WgAllowedIpAttrs::IpAddr(_) => WGALLOWEDIP_A_IPADDR,
            WgAllowedIpAttrs::Cidr(_) => WGALLOWEDIP_A_CIDR_MASK,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            WgAllowedIpAttrs::Unspec(bytes) => buffer.copy_from_slice(bytes),
            WgAllowedIpAttrs::Family(v) => NativeEndian::write_u16(buffer, *v),
            WgAllowedIpAttrs::IpAddr(v) => emit_ip(v, buffer),
            WgAllowedIpAttrs::Cidr(v) => buffer[0] = *v,
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for WgAllowedIpAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            WGALLOWEDIP_A_UNSPEC => Self::Unspec(payload.to_vec()),
            WGALLOWEDIP_A_FAMILY => {
                Self::Family(parse_u16(payload).context("invalid WGALLOWEDIP_A_FAMILY value")?)
            }
            WGALLOWEDIP_A_IPADDR => {
                Self::IpAddr(parse_ip(payload).context("invalid WGALLOWEDIP_A_IPADDR value")?)
            }
            WGALLOWEDIP_A_CIDR_MASK => Self::Cidr(payload[0]),
            kind => return Err(DecodeError::from(format!("invalid NLA kind: {}", kind))),
        })
    }
}
