mod config;
pub use self::config::*;

mod stats;
pub use self::stats::*;

use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{
    rtnl::{
        nla::{DefaultNla, Nla, NlaBuffer},
        traits::Parseable,
        utils::{parse_string, parse_u32, parse_u64},
    },
    DecodeError,
};

pub const NDTA_UNSPEC: u16 = 0;
pub const NDTA_NAME: u16 = 1;
pub const NDTA_THRESH1: u16 = 2;
pub const NDTA_THRESH2: u16 = 3;
pub const NDTA_THRESH3: u16 = 4;
pub const NDTA_CONFIG: u16 = 5;
pub const NDTA_PARMS: u16 = 6;
pub const NDTA_STATS: u16 = 7;
pub const NDTA_GC_INTERVAL: u16 = 8;
pub const NDTA_PAD: u16 = 9;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NeighbourTableNla {
    Unspec(Vec<u8>),
    // FIXME: parse this nla
    Parms(Vec<u8>),
    Name(String),
    Threshold1(u32),
    Threshold2(u32),
    Threshold3(u32),
    Config(Vec<u8>),
    Stats(Vec<u8>),
    GcInterval(u64),
    Other(DefaultNla),
}

impl Nla for NeighbourTableNla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::NeighbourTableNla::*;
        match *self {
            Unspec(ref bytes) | Parms(ref bytes) | Config(ref bytes) | Stats(ref bytes)=> bytes.len(),
            // strings: +1 because we need to append a nul byte
            Name(ref s) => s.len() + 1,
            Threshold1(_) | Threshold2(_) | Threshold3(_) => size_of::<u32>(),
            GcInterval(_) => size_of::<u64>(),
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::NeighbourTableNla::*;
        match *self {
            Unspec(ref bytes) | Parms(ref bytes) | Config(ref bytes) | Stats(ref bytes) => {
                buffer.copy_from_slice(bytes.as_slice())
            }
            Name(ref string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            GcInterval(ref value) => NativeEndian::write_u64(buffer, *value),
            Threshold1(ref value) | Threshold2(ref value) | Threshold3(ref value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::NeighbourTableNla::*;
        match *self {
            Unspec(_) => NDTA_UNSPEC,
            Name(_) => NDTA_NAME,
            Config(_) => NDTA_CONFIG,
            Stats(_) => NDTA_STATS,
            Parms(_) => NDTA_PARMS,
            GcInterval(_) => NDTA_GC_INTERVAL,
            Threshold1(_) => NDTA_THRESH1,
            Threshold2(_) => NDTA_THRESH2,
            Threshold3(_) => NDTA_THRESH3,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NeighbourTableNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<NeighbourTableNla, DecodeError> {
        use self::NeighbourTableNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            NDTA_UNSPEC => Unspec(payload.to_vec()),
            NDTA_NAME => Name(parse_string(payload).context("invalid NDTA_NAME value")?),
            NDTA_CONFIG => Config(payload.to_vec()),
            NDTA_STATS => Stats(payload.to_vec()),
            NDTA_PARMS => Parms(payload.to_vec()),
            NDTA_GC_INTERVAL => {
                GcInterval(parse_u64(payload).context("invalid NDTA_GC_INTERVAL value")?)
            }
            NDTA_THRESH1 => Threshold1(parse_u32(payload).context("invalid NDTA_THRESH1 value")?),
            NDTA_THRESH2 => Threshold2(parse_u32(payload).context("invalid NDTA_THRESH2 value")?),
            NDTA_THRESH3 => Threshold3(parse_u32(payload).context("invalid NDTA_THRESH3 value")?),
            kind => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context(format!("unknown NLA type {}", kind))?,
            ),
        })
    }
}
