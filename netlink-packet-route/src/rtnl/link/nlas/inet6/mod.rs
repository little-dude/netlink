use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{
    rtnl::{
        link::nlas::{
            IFLA_INET6_ADDR_GEN_MODE, IFLA_INET6_CACHEINFO, IFLA_INET6_CONF, IFLA_INET6_FLAGS,
            IFLA_INET6_ICMP6STATS, IFLA_INET6_STATS, IFLA_INET6_TOKEN, IFLA_INET6_UNSPEC,
        },
        nla::{DefaultNla, Nla, NlaBuffer},
        traits::Parseable,
        utils::{parse_ipv6, parse_u32, parse_u8},
    },
    DecodeError,
};

mod cache;
pub use self::cache::*;
mod dev_conf;
pub use self::dev_conf::*;
mod icmp6_stats;
pub use self::icmp6_stats::*;
mod stats;
pub use self::stats::*;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum LinkAfInet6Nla {
    Flags(u32),
    CacheInfo(Vec<u8>),
    // LinkInet6DevConf is big (198 bytes), so we're wasting a space for each variant without a box.
    DevConf(Vec<u8>),
    Unspec(Vec<u8>),
    // LinkInet6Stats is huge (288 bytes), so we're wasting a *lot* of space for each variant without a
    // box.
    Stats(Vec<u8>),
    IcmpStats(Vec<u8>),
    Token([u8; 16]),
    AddrGenMode(u8),
    Other(DefaultNla),
}

impl Nla for LinkAfInet6Nla {
    fn value_len(&self) -> usize {
        use self::LinkAfInet6Nla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            CacheInfo(ref cache_info) => cache_info.len(),
            DevConf(ref dev_conf) => dev_conf.len(),
            Stats(ref stats) => stats.len(),
            IcmpStats(ref icmp_stats) => icmp_stats.len(),
            Flags(_) => 4,
            Token(_) => 16,
            AddrGenMode(_) => 1,
            Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkAfInet6Nla::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Flags(ref value) => NativeEndian::write_u32(buffer, *value),
            CacheInfo(ref cache_info) => buffer.copy_from_slice(cache_info.as_slice()),
            DevConf(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Stats(ref inet6_stats) => buffer.copy_from_slice(inet6_stats.as_slice()),
            IcmpStats(ref icmp6_stats) => buffer.copy_from_slice(icmp6_stats.as_slice()),
            Token(ref ipv6) => buffer.copy_from_slice(&ipv6[..]),
            AddrGenMode(value) => buffer[0] = value,
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkAfInet6Nla::*;
        match *self {
            Unspec(_) => IFLA_INET6_UNSPEC,
            Flags(_) => IFLA_INET6_FLAGS,
            CacheInfo(_) => IFLA_INET6_CACHEINFO,
            DevConf(_) => IFLA_INET6_CONF,
            Stats(_) => IFLA_INET6_STATS,
            IcmpStats(_) => IFLA_INET6_ICMP6STATS,
            Token(_) => IFLA_INET6_TOKEN,
            AddrGenMode(_) => IFLA_INET6_ADDR_GEN_MODE,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkAfInet6Nla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<LinkAfInet6Nla, DecodeError> {
        use self::LinkAfInet6Nla::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFLA_INET6_UNSPEC => Unspec(payload.to_vec()),
            IFLA_INET6_FLAGS => {
                Flags(parse_u32(payload).context("invalid IFLA_INET6_FLAGS value")?)
            }
            IFLA_INET6_CACHEINFO => CacheInfo(payload.to_vec()),
            IFLA_INET6_CONF => DevConf(payload.to_vec()),
            IFLA_INET6_STATS => Stats(payload.to_vec()),
            IFLA_INET6_ICMP6STATS => IcmpStats(payload.to_vec()),
            IFLA_INET6_TOKEN => {
                Token(parse_ipv6(payload).context("invalid IFLA_INET6_TOKEN value")?)
            }
            IFLA_INET6_ADDR_GEN_MODE => {
                AddrGenMode(parse_u8(payload).context("invalid IFLA_INET6_ADDR_GEN_MODE value")?)
            }
            kind => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context(format!("unknown NLA type {}", kind))?,
            ),
        })
    }
}
