mod metrics;

pub use self::metrics::RouteMetricsNla;
use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;
use std::mem::size_of;

use constants::*;
use utils::{parse_u16, parse_u32};
use {DecodeError, DefaultNla, Emitable, Nla, NlaBuffer, Parseable};

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

const ROUTE_CACHE_INFO_LEN: usize = 4*8;

impl RouteCacheInfo {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < ROUTE_CACHE_INFO_LEN {
            return Err(DecodeError::from(format!(
                "RTA_CACHEINFO is {} bytes, buffer is only {} bytes: {:#x?}",
                ROUTE_CACHE_INFO_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(RouteCacheInfo {
            clntref: NativeEndian::read_u32(&buf[0..4]),
            last_use: NativeEndian::read_u32(&buf[4..8]),
            expires: NativeEndian::read_u32(&buf[8..12]),
            error: NativeEndian::read_u32(&buf[12..16]),
            used: NativeEndian::read_u32(&buf[16..20]),
            id: NativeEndian::read_u32(&buf[20..24]),
            ts: NativeEndian::read_u32(&buf[24..28]),
            ts_age: NativeEndian::read_u32(&buf[28..32]),
        })
    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < ROUTE_CACHE_INFO_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but RTA_CACHEINFO is {} bytes",
                buf.len(),
               ROUTE_CACHE_INFO_LEN,
            )));
        }
        NativeEndian::write_u32(&mut buf[0..4], self.clntref);
        NativeEndian::write_u32(&mut buf[4..8], self.last_use);
        NativeEndian::write_u32(&mut buf[8..12], self.expires);
        NativeEndian::write_u32(&mut buf[12..16], self.error);
        NativeEndian::write_u32(&mut buf[16..20], self.used);
        NativeEndian::write_u32(&mut buf[20..24], self.id);
        NativeEndian::write_u32(&mut buf[24..28], self.ts);
        NativeEndian::write_u32(&mut buf[28..32], self.ts_age);
        Ok(())
    }
}


#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RouteMfcStats {
    pub packets: u64,
    pub bytes: u64,
    pub wrong_if: u64,
}

const ROUTE_MFC_STATS_LEN: usize = 3*8;

impl RouteMfcStats {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < ROUTE_MFC_STATS_LEN {
            return Err(DecodeError::from(format!(
                "RTA_MFC_STATS is {} bytes, buffer is only {} bytes: {:#x?}",
                ROUTE_MFC_STATS_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(RouteMfcStats {
            packets: NativeEndian::read_u64(&buf[0..8]),
            bytes: NativeEndian::read_u64(&buf[8..16]),
            wrong_if: NativeEndian::read_u64(&buf[16..24]),
        })
    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < ROUTE_MFC_STATS_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but RTA_CACHEINFO is {} bytes",
                buf.len(),
               ROUTE_MFC_STATS_LEN,
            )));
        }
        NativeEndian::write_u64(&mut buf[0..8], self.packets);
        NativeEndian::write_u64(&mut buf[8..16], self.bytes);
        NativeEndian::write_u64(&mut buf[16..24], self.wrong_if);
        Ok(())
    }
}

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
            CacheInfo(ref cache_info) => cache_info.to_bytes(buffer).expect("check the buffer length before calling emit_value()!"),
            MfcStats(ref mfc_stats) => mfc_stats.to_bytes(buffer).expect("check the buffer length before calling emit_value()!"),
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
            RTA_CACHEINFO => CacheInfo(
                RouteCacheInfo::from_bytes(payload).context("invalid RTA_CACHEINFO value")?,
            ),
            RTA_MFC_STATS => {
                MfcStats(RouteMfcStats::from_bytes(payload).context("invalid RTA_MFC_STATS value")?)
            }
            RTA_METRICS => Metrics(
                NlaBuffer::new_checked(payload)
                    .context("invalid RTA_METRICS value")?
                    .parse()
                    .context("invalid RTA_METRICS value")?,
            ),
            _ => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
