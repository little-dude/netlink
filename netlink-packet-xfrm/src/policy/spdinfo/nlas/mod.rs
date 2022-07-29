// SPDX-License-Identifier: MIT

pub mod spd_info;
pub use spd_info::*;

use anyhow::Context;

use crate::constants::*;

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SpdInfoAttrs {
    Unspec(Vec<u8>),
    SpdInfo(spd_info::SpdInfo),
    SpdHInfo(spd_info::SpdHInfo),
    SpdIpv4HThresh(spd_info::SpdHThresh),
    SpdIpv6HThresh(spd_info::SpdHThresh),
    Other(DefaultNla),
}

impl Nla for SpdInfoAttrs {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::SpdInfoAttrs::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            SpdInfo(ref v) => v.buffer_len(),
            SpdHInfo(ref v) => v.buffer_len(),
            SpdIpv4HThresh(ref v) => v.buffer_len(),
            SpdIpv6HThresh(ref v) => v.buffer_len(),
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::SpdInfoAttrs::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            SpdInfo(ref v) => v.emit(buffer),
            SpdHInfo(ref v) => v.emit(buffer),
            SpdIpv4HThresh(ref v) => v.emit(buffer),
            SpdIpv6HThresh(ref v) => v.emit(buffer),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::SpdInfoAttrs::*;
        match *self {
            Unspec(_) => XFRMA_SPD_UNSPEC,
            SpdInfo(_) => XFRMA_SPD_INFO,
            SpdHInfo(_) => XFRMA_SPD_HINFO,
            SpdIpv4HThresh(_) => XFRMA_SPD_IPV4_HTHRESH,
            SpdIpv6HThresh(_) => XFRMA_SPD_IPV6_HTHRESH,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for SpdInfoAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::SpdInfoAttrs::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            XFRMA_SPD_UNSPEC => Unspec(payload.to_vec()),
            XFRMA_SPD_INFO => SpdInfo(spd_info::SpdInfo::parse(&SpdInfoBuffer::new(payload)).context("invalid XFRMA_SPD_INFO")?),
            XFRMA_SPD_HINFO => SpdHInfo(spd_info::SpdHInfo::parse(&SpdHInfoBuffer::new(payload)).context("invalid XFRMA_SPD_HINFO")?),
            XFRMA_SPD_IPV4_HTHRESH => SpdIpv4HThresh(spd_info::SpdHThresh::parse(&SpdHThreshBuffer::new(payload)).context("invalid XFRMA_SPD_IPV4_HTHRESH")?),
            XFRMA_SPD_IPV6_HTHRESH => SpdIpv6HThresh(spd_info::SpdHThresh::parse(&SpdHThreshBuffer::new(payload)).context("invalid XFRMA_SPD_IPV6_HTHRESH")?),
            kind => Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?),
        })
    }
}
