use std::mem::size_of;

use utils::{parse_string, parse_u8};
use {DefaultNla, NativeNla, Nla, NlaBuffer, Parseable, Result, NlasIterator, Emitable};

use constants::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TcNla {
    Unspec(Vec<u8>),
    Kind(String),
    Options(Vec<u8>),
    Stats(TcStats),
    XStats(Vec<u8>),
    Rate(Vec<u8>),
    FCNT(Vec<u8>),
    Stats2(Vec<TcStats2Nla>),
    Stab(Vec<u8>),
    HwOffload(u8),
    Other(DefaultNla),
}

impl Nla for TcNla {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::TcNla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Options(ref bytes)
                | XStats(ref bytes)
                | Rate(ref bytes)
                | FCNT(ref bytes)
                | Stab(ref bytes) => bytes.len(),
            HwOffload(_) => size_of::<u8>(),
            Stats2(ref thing) => thing.as_slice().buffer_len(),
            Stats(_) => size_of::<TcStats>(),
            Kind(ref string) => string.as_bytes().len() + 1,

            // Defaults
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::TcNla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Options(ref bytes)
                | XStats(ref bytes)
                | Rate(ref bytes)
                | FCNT(ref bytes)
                | Stab(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            HwOffload(ref val) => buffer[0] = *val,
            Stats2(ref stats) => stats.as_slice().emit(buffer),
            Stats(ref stats) => stats.to_bytes(buffer),

            Kind(ref string) => {
                buffer.copy_from_slice(string.as_bytes());
                buffer[string.as_bytes().len()] = 0;
            }

            // Default
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::TcNla::*;
        match *self {
            Unspec(_) => TCA_UNSPEC,
            Kind(_) => TCA_KIND,
            Options(_) => TCA_OPTIONS,
            Stats(_) => TCA_STATS,
            XStats(_) => TCA_XSTATS,
            Rate(_) => TCA_RATE,
            FCNT(_) => TCA_FCNT,
            Stats2(_) => TCA_STATS2,
            Stab(_) => TCA_STAB,
            HwOffload(_) => TCA_HW_OFFLOAD,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<TcNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<TcNla> {
        use self::TcNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            TCA_UNSPEC => Unspec(payload.to_vec()),
            TCA_KIND => Kind(parse_string(payload)?),
            TCA_OPTIONS => Options(payload.to_vec()),
            TCA_STATS => Stats(TcStats::from_bytes(payload)?),
            TCA_XSTATS => XStats(payload.to_vec()),
            TCA_RATE => Rate(payload.to_vec()),
            TCA_FCNT => FCNT(payload.to_vec()),
            TCA_STATS2 => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    nlas.push(<Parseable<TcStats2Nla>>::parse(&(nla?))?);
                }
                Stats2(nlas)
            }
            TCA_STAB => Stab(payload.to_vec()),
            TCA_HW_OFFLOAD => HwOffload(parse_u8(payload)?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcStats {
    pub bytes: u64,
    pub packets: u32,
    pub drops: u32,
    pub overlimits: u32,
    pub bps: u32,
    pub pps: u32,
    pub qlen: u32,
    pub backlog: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcStatsBasic {
    pub bytes: u64,
    pub packets: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcStatsQueue {
    pub qlen: u32,
    pub backlog: u32,
    pub drops: u32,
    pub requeues: u32,
    pub overlimits: u32,
}

impl NativeNla for TcStatsQueue {}
impl NativeNla for TcStatsBasic {}
impl NativeNla for TcStats {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TcStats2Nla {
    StatsApp(Vec<u8>),
    StatsBasic(TcStatsBasic),
    StatsQueue(TcStatsQueue),
    Other(DefaultNla),
}

impl Nla for TcStats2Nla {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::TcStats2Nla::*;
        match *self {
            StatsApp(ref bytes) => bytes.len(),
            StatsBasic(_) => size_of::<TcStatsBasic>(),
            StatsQueue(_) => size_of::<TcStatsQueue>(),
            Other(ref nla) => nla.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::TcStats2Nla::*;
        match *self {
            StatsApp(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            StatsBasic(ref nla) => nla.to_bytes(buffer),
            StatsQueue(ref nla) => nla.to_bytes(buffer),
            Other(ref nla)  => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::TcStats2Nla::*;
        match *self {
            StatsApp(_) => 4u16,
            StatsBasic(_) => 1u16,
            StatsQueue(_) => 3u16,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<TcStats2Nla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<TcStats2Nla> {
        use self::TcStats2Nla::*;
        let payload = self.value();
        Ok(match self.kind() {
            4u16 => StatsApp(payload.to_vec()),
            1u16 => StatsBasic(TcStatsBasic::from_bytes(payload)?),
            3u16 => StatsQueue(TcStatsQueue::from_bytes(payload)?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}
