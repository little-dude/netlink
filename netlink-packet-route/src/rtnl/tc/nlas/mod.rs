// SPDX-License-Identifier: MIT

mod stats;
use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};

pub use self::stats::*;
use self::{class::TcHtb::TcHtbOpt, Htb::HtbGlob};

mod stats_queue;
pub use self::stats_queue::*;

mod stats_basic;
pub use self::stats_basic::*;

mod options;
pub use self::options::*;

mod qdisc;
pub use self::qdisc::*;

mod filter;
pub use self::filter::*;

mod action;
pub use self::action::*;

mod class;
pub use self::class::*;

#[cfg(test)]
mod test;

use crate::{
    constants::*,
    nlas::{self, DefaultNla, NlaBuffer},
    traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    /// Unspecified
    Unspec(Vec<u8>),
    /// Name of queueing discipline
    Kind(String),
    /// Options follow
    Options(Vec<TcOpt>),
    /// Statistics
    Stats(Stats),
    /// Module-specific statistics
    XStats(Vec<u8>),
    /// Rate limit
    Rate(Vec<u8>),
    Fcnt(Vec<u8>),
    Stats2(Vec<Stats2>),
    Stab(Vec<u8>),
    Chain(Vec<u8>),
    HwOffload(u8),
    HtbOpt(HtbGlob),
    TcRate(u64),
    TcCeil(u64),
    TcHtbOpt1(TcHtbOpt),
    TcHtbRtab([u32; 256]),
    TcHtbCtab([u32; 256]),
    Other(DefaultNla),
}

impl nlas::Nla for Nla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes) | XStats(ref bytes) | Rate(ref bytes) | Fcnt(ref bytes)
            | Stab(ref bytes) | Chain(ref bytes) => bytes.len(),
            HwOffload(_) => 1,
            Stats2(ref thing) => thing.as_slice().buffer_len(),
            Stats(_) => STATS_LEN,
            Kind(ref string) => string.as_bytes().len() + 1,
            Options(ref opt) => opt.as_slice().buffer_len(),
            HtbOpt(_) => return size_of::<HtbGlob>(),
            // Defaults
            Other(ref attr) => attr.value_len(),
            TcHtbOpt1(ref opt) => opt.rate.buffer_len() + opt.ceil.buffer_len() + 4 * 5,
            TcHtbRtab(_) => 1024,
            TcHtbCtab(_) => 1024,
            TcRate(_) | TcCeil(_) => 8,
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | XStats(ref bytes)
                | Rate(ref bytes)
                | Fcnt(ref bytes)
                | Stab(ref bytes)
                | Chain(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            HwOffload(ref val) => buffer[0] = *val,
            Stats2(ref stats) => stats.as_slice().emit(buffer),
            Stats(ref stats) => stats.emit(buffer),

            Kind(ref string) => {
                buffer[..string.as_bytes().len()].copy_from_slice(string.as_bytes());
                buffer[string.as_bytes().len()] = 0;
            }
            Options(ref opt) => opt.as_slice().emit(buffer),
            HtbOpt(ref opt) => {
                NativeEndian::write_u32(buffer, opt.version);
                NativeEndian::write_u32(buffer, opt.rate2quatum);
                NativeEndian::write_u32(buffer, opt.defcls);
                NativeEndian::write_u32(buffer, opt.debug);
                NativeEndian::write_u32(buffer, opt.direct_pkts);
            },

            // Default
            Other(ref attr) => attr.emit_value(buffer),
            TcHtbOpt1(_) => todo!(),
            TcHtbRtab(_) => todo!(),
            TcHtbCtab(_) => todo!(),
            TcRate(n) | TcCeil(n) => NativeEndian::write_u64(buffer, n),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Unspec(_) => TCA_UNSPEC,
            Kind(_) => TCA_KIND,
            Options(_) => TCA_OPTIONS,
            Stats(_) => TCA_STATS,
            XStats(_) => TCA_XSTATS,
            Rate(_) => TCA_RATE,
            Fcnt(_) => TCA_FCNT,
            Stats2(_) => TCA_STATS2,
            Stab(_) => TCA_STAB,
            Chain(_) => TCA_CHAIN,
            HwOffload(_) => TCA_HW_OFFLOAD,
            HtbOpt(_) => TCA_HTB_INIT,
            TcHtbOpt1(_) => TCA_HTB_PARMS,
            Other(ref nla) => nla.kind(),
            TcHtbRtab(_) => TCA_HTB_RTAB,
            TcHtbCtab(_) => TCA_HTB_CTAB,
            TcRate(_) => TCA_HTB_RATE64,
            TcCeil(_) => TCA_HTB_CEIL64,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Stats2 {
    StatsApp(Vec<u8>),
    StatsBasic(Vec<u8>),
    StatsQueue(Vec<u8>),
    Other(DefaultNla),
}

impl nlas::Nla for Stats2 {
    fn value_len(&self) -> usize {
        use self::Stats2::*;
        match *self {
            StatsBasic(ref bytes) | StatsQueue(ref bytes) | StatsApp(ref bytes) => bytes.len(),
            Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Stats2::*;
        match *self {
            StatsBasic(ref bytes) | StatsQueue(ref bytes) | StatsApp(ref bytes) => {
                buffer.copy_from_slice(bytes.as_slice())
            }
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Stats2::*;
        match *self {
            StatsApp(_) => TCA_STATS_APP,
            StatsBasic(_) => TCA_STATS_BASIC,
            StatsQueue(_) => TCA_STATS_QUEUE,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Stats2 {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_STATS_APP => Self::StatsApp(payload.to_vec()),
            TCA_STATS_BASIC => Self::StatsBasic(payload.to_vec()),
            TCA_STATS_QUEUE => Self::StatsQueue(payload.to_vec()),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
