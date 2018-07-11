mod metrics;

pub use self::metrics::RouteMetricsNla;
use byteorder::{ByteOrder, NativeEndian};
use std::mem::size_of;

use constants::*;
use utils::{parse_u16, parse_u32};
use {DefaultNla, Emitable, NativeNla, Nla, NlaBuffer, Parseable, Result};

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RouteCacheInfo {
    pub clntref: u32,
    pub last_use: u32,
    pub expires: u32,
    pub error: u32,
    pub used: u32,
    pub id: u32,
    pub ts: u32,
    pub ts_age: u32,
}

impl NativeNla for RouteCacheInfo {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RouteMfcStats {
    pub packets: u64,
    pub bytes: u64,
    pub wrong_if: u64,
}

impl NativeNla for RouteMfcStats {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouteNla {
    Unspec(Vec<u8>),
    Destination(Vec<u8>),
    Source(Vec<u8>),
    Gateway(Vec<u8>),
    PrefSource(Vec<u8>),
    Metrics(RouteMetricsNla),
    MultiPath(Vec<u8>),
    CacheInfo(RouteCacheInfo),
    Session(Vec<u8>),
    MpAlgo(Vec<u8>),
    MfcStats(RouteMfcStats),
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
    #[cfg_attr(nightly, rustfmt::skip)]
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

            CacheInfo(_) => size_of::<RouteCacheInfo>(),
            MfcStats(_) => size_of::<RouteMfcStats>(),
            Metrics(ref attr) => attr.buffer_len(),
            Other(ref attr) => attr.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
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
            CacheInfo(ref cache_info) => cache_info.to_bytes(buffer),
            MfcStats(ref mfc_stats) => mfc_stats.to_bytes(buffer),
            Metrics(ref attr) => attr.emit(buffer),
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
    fn parse(&self) -> Result<RouteNla> {
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
            RTA_ENCAP_TYPE => EncapType(parse_u16(payload)?),
            RTA_IIF => Iif(parse_u32(payload)?),
            RTA_OIF => Oif(parse_u32(payload)?),
            RTA_PRIORITY => Priority(parse_u32(payload)?),
            RTA_PROTOINFO => ProtocolInfo(parse_u32(payload)?),
            RTA_FLOW => Flow(parse_u32(payload)?),
            RTA_TABLE => Table(parse_u32(payload)?),
            RTA_MARK => Mark(parse_u32(payload)?),
            RTA_CACHEINFO => CacheInfo(RouteCacheInfo::from_bytes(payload)?),
            RTA_MFC_STATS => MfcStats(RouteMfcStats::from_bytes(payload)?),
            RTA_METRICS => Metrics(NlaBuffer::new_checked(payload)?.parse()?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}
