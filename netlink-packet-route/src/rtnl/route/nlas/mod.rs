mod metrics;
pub use self::metrics::*;

mod cache_info;
pub use self::cache_info::*;

mod mfc_stats;
pub use self::mfc_stats::*;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;
use std::mem::size_of;

use crate::{
    rtnl::{
        nla::{DefaultNla, Nla, NlaBuffer},
        traits::Parseable,
        utils::{parse_u16, parse_u32},
    },
    DecodeError,
};

pub const RTA_UNSPEC: u16 = 0;
pub const RTA_DST: u16 = 1;
pub const RTA_SRC: u16 = 2;
pub const RTA_IIF: u16 = 3;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_METRICS: u16 = 8;
pub const RTA_MULTIPATH: u16 = 9;
pub const RTA_PROTOINFO: u16 = 10;
pub const RTA_FLOW: u16 = 11;
pub const RTA_CACHEINFO: u16 = 12;
pub const RTA_SESSION: u16 = 13;
pub const RTA_MP_ALGO: u16 = 14;
pub const RTA_TABLE: u16 = 15;
pub const RTA_MARK: u16 = 16;
pub const RTA_MFC_STATS: u16 = 17;
pub const RTA_VIA: u16 = 18;
pub const RTA_NEWDST: u16 = 19;
pub const RTA_PREF: u16 = 20;
pub const RTA_ENCAP_TYPE: u16 = 21;
pub const RTA_ENCAP: u16 = 22;
pub const RTA_EXPIRES: u16 = 23;
pub const RTA_PAD: u16 = 24;
pub const RTA_UID: u16 = 25;
pub const RTA_TTL_PROPAGATE: u16 = 26;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouteNla {
    Unspec(Vec<u8>),
    Destination(Vec<u8>),
    Source(Vec<u8>),
    Gateway(Vec<u8>),
    PrefSource(Vec<u8>),
    Metrics(Vec<u8>),
    MultiPath(Vec<u8>),
    CacheInfo(Vec<u8>),
    Session(Vec<u8>),
    MpAlgo(Vec<u8>),
    MfcStats(Vec<u8>),
    Via(Vec<u8>),
    NewDestination(Vec<u8>),
    Pref(Vec<u8>),
    Encap(Vec<u8>),
    Expires(Vec<u8>),
    Pad(Vec<u8>),
    Uid(Vec<u8>),
    TtlPropagate(Vec<u8>),
    EncapType(u16),
    Iif(u32),
    Oif(u32),
    Priority(u32),
    ProtocolInfo(u32),
    Flow(u32),
    Table(u32),
    Mark(u32),
    Other(DefaultNla),
}

impl Nla for RouteNla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::RouteNla::*;
        match *self {
            Unspec(ref bytes)
                | Destination(ref bytes)
                | Source(ref bytes)
                | Gateway(ref bytes)
                | PrefSource(ref bytes)
                | MultiPath(ref bytes)
                | Session(ref bytes)
                | MpAlgo(ref bytes)
                | Via(ref bytes)
                | NewDestination(ref bytes)
                | Pref(ref bytes)
                | Encap(ref bytes)
                | Expires(ref bytes)
                | Pad(ref bytes)
                | Uid(ref bytes)
                | TtlPropagate(ref bytes)
                | CacheInfo(ref bytes)
                | MfcStats(ref bytes)
                | Metrics(ref bytes)
                => bytes.len(),

            EncapType(_) => size_of::<u16>(),
            Iif(_)
                | Oif(_)
                | Priority(_)
                | ProtocolInfo(_)
                | Flow(_)
                | Table(_)
                | Mark(_)
                => size_of::<u32>(),

            Other(ref attr) => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::RouteNla::*;
        match *self {
            Unspec(ref bytes)
                | Destination(ref bytes)
                | Source(ref bytes)
                | Gateway(ref bytes)
                | PrefSource(ref bytes)
                | MultiPath(ref bytes)
                | Session(ref bytes)
                | MpAlgo(ref bytes)
                | Via(ref bytes)
                | NewDestination(ref bytes)
                | Pref(ref bytes)
                | Encap(ref bytes)
                | Expires(ref bytes)
                | Pad(ref bytes)
                | Uid(ref bytes)
                | TtlPropagate(ref bytes)
                | CacheInfo(ref bytes)
                | MfcStats(ref bytes)
                | Metrics(ref bytes)
                => buffer.copy_from_slice(bytes.as_slice()),
            EncapType(value) => NativeEndian::write_u16(buffer, value),
            Iif(value)
                | Oif(value)
                | Priority(value)
                | ProtocolInfo(value)
                | Flow(value)
                | Table(value)
                | Mark(value)
                => NativeEndian::write_u32(buffer, value),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::RouteNla::*;
        match *self {
            Unspec(_) => RTA_UNSPEC,
            Destination(_) => RTA_DST,
            Source(_) => RTA_SRC,
            Iif(_) => RTA_IIF,
            Oif(_) => RTA_OIF,
            Gateway(_) => RTA_GATEWAY,
            Priority(_) => RTA_PRIORITY,
            PrefSource(_) => RTA_PREFSRC,
            Metrics(_) => RTA_METRICS,
            MultiPath(_) => RTA_MULTIPATH,
            ProtocolInfo(_) => RTA_PROTOINFO,
            Flow(_) => RTA_FLOW,
            CacheInfo(_) => RTA_CACHEINFO,
            Session(_) => RTA_SESSION,
            MpAlgo(_) => RTA_MP_ALGO,
            Table(_) => RTA_TABLE,
            Mark(_) => RTA_MARK,
            MfcStats(_) => RTA_MFC_STATS,
            Via(_) => RTA_VIA,
            NewDestination(_) => RTA_NEWDST,
            Pref(_) => RTA_PREF,
            EncapType(_) => RTA_ENCAP_TYPE,
            Encap(_) => RTA_ENCAP,
            Expires(_) => RTA_EXPIRES,
            Pad(_) => RTA_PAD,
            Uid(_) => RTA_UID,
            TtlPropagate(_) => RTA_TTL_PROPAGATE,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<RouteNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<RouteNla, DecodeError> {
        use self::RouteNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            RTA_UNSPEC => Unspec(payload.to_vec()),
            RTA_DST => Destination(payload.to_vec()),
            RTA_SRC => Source(payload.to_vec()),
            RTA_GATEWAY => Gateway(payload.to_vec()),
            RTA_PREFSRC => PrefSource(payload.to_vec()),
            RTA_MULTIPATH => MultiPath(payload.to_vec()),
            RTA_SESSION => Session(payload.to_vec()),
            RTA_MP_ALGO => MpAlgo(payload.to_vec()),
            RTA_VIA => Via(payload.to_vec()),
            RTA_NEWDST => NewDestination(payload.to_vec()),
            RTA_PREF => Pref(payload.to_vec()),
            RTA_ENCAP => Encap(payload.to_vec()),
            RTA_EXPIRES => Expires(payload.to_vec()),
            RTA_PAD => Pad(payload.to_vec()),
            RTA_UID => Uid(payload.to_vec()),
            RTA_TTL_PROPAGATE => TtlPropagate(payload.to_vec()),
            RTA_ENCAP_TYPE => {
                EncapType(parse_u16(payload).context("invalid RTA_ENCAP_TYPE value")?)
            }
            RTA_IIF => Iif(parse_u32(payload).context("invalid RTA_IIF value")?),
            RTA_OIF => Oif(parse_u32(payload).context("invalid RTA_OIF value")?),
            RTA_PRIORITY => Priority(parse_u32(payload).context("invalid RTA_PRIORITY value")?),
            RTA_PROTOINFO => {
                ProtocolInfo(parse_u32(payload).context("invalid RTA_PROTOINFO value")?)
            }
            RTA_FLOW => Flow(parse_u32(payload).context("invalid RTA_FLOW value")?),
            RTA_TABLE => Table(parse_u32(payload).context("invalid RTA_TABLE value")?),
            RTA_MARK => Mark(parse_u32(payload).context("invalid RTA_MARK value")?),
            RTA_CACHEINFO => CacheInfo(payload.to_vec()),
            RTA_MFC_STATS => MfcStats(payload.to_vec()),
            RTA_METRICS => Metrics(payload.to_vec()),
            _ => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
