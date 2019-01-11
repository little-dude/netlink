mod config;
pub use self::config::*;

mod stats;
pub use self::stats::*;

use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::constants::*;
use crate::utils::{parse_string, parse_u32, parse_u64};
use crate::{DecodeError, DefaultNla, Emitable, Nla, NlaBuffer, Parseable};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NeighbourTableNla {
    Unspec(Vec<u8>),
    // FIXME: parse this nla
    Parms(Vec<u8>),
    Name(String),
    Threshold1(u32),
    Threshold2(u32),
    Threshold3(u32),
    Config(NeighbourTableConfig),
    Stats(NeighbourTableStats),
    GcInterval(u64),
    Other(DefaultNla),
}

impl Nla for NeighbourTableNla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::NeighbourTableNla::*;
        match *self {
            Unspec(ref bytes) | Parms(ref bytes) => bytes.len(),
            // strings: +1 because we need to append a nul byte
            Name(ref s) => s.len() + 1,
            Threshold1(_) | Threshold2(_) | Threshold3(_) => size_of::<u32>(),
            GcInterval(_) => size_of::<u64>(),
            Config(_) => NEIGHBOUR_TABLE_CONFIG_LEN,
            Stats(_) => NEIGHBOUR_TABLE_STATS_LEN,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::NeighbourTableNla::*;
        match *self {
            Unspec(ref bytes) | Parms(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Name(ref string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Config(ref config) => config.emit(buffer),
            Stats(ref stats) => stats.emit(buffer),
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
            NDTA_CONFIG => Config(
                NeighbourTableConfigBuffer::new(payload)
                    .parse()
                    .context("invalid NDTA_CONFIG value")?,
            ),
            NDTA_STATS => Stats(
                NeighbourTableStatsBuffer::new(payload)
                    .parse()
                    .context("invalid NDTA_STATS value")?,
            ),
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
