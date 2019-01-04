use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::constants::*;
use crate::utils::{parse_ipv6, parse_u32, parse_u8};
use crate::{DecodeError, DefaultNla, Emitable, Nla, NlaBuffer, Parseable};

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
    CacheInfo(LinkInet6CacheInfo),
    // LinkInet6DevConf is big (198 bytes), so we're wasting a space for each variant without a box.
    DevConf(Box<LinkInet6DevConf>),
    Unspec(Vec<u8>),
    // LinkInet6Stats is huge (288 bytes), so we're wasting a *lot* of space for each variant without a
    // box.
    Stats(Box<LinkInet6Stats>),
    IcmpStats(LinkIcmp6Stats),
    Token([u8; 16]),
    AddrGenMode(u8),
    Other(DefaultNla),
}

impl Nla for LinkAfInet6Nla {
    fn value_len(&self) -> usize {
        use self::LinkAfInet6Nla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            CacheInfo(ref cache_info) => cache_info.buffer_len(),
            DevConf(ref dev_conf) => dev_conf.buffer_len(),
            Stats(ref stats) => stats.buffer_len(),
            IcmpStats(ref icmp_stats) => icmp_stats.buffer_len(),
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
            CacheInfo(ref cache_info) => cache_info.emit(buffer),
            DevConf(ref inet6_dev_conf) => inet6_dev_conf.emit(buffer),
            Stats(ref inet6_stats) => inet6_stats.emit(buffer),
            IcmpStats(ref icmp6_stats) => icmp6_stats.emit(buffer),
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
            IFLA_INET6_CACHEINFO => CacheInfo(
                LinkInet6CacheInfoBuffer::new(payload)
                    .parse()
                    .context("invalid IFLA_INET6_CACHEINFO value")?,
            ),
            IFLA_INET6_CONF => DevConf(Box::new(
                LinkInet6DevConfBuffer::new(payload)
                    .parse()
                    .context("invalid IFLA_INET6_CONF value")?,
            )),
            IFLA_INET6_STATS => Stats(Box::new(
                LinkInet6StatsBuffer::new(payload)
                    .parse()
                    .context("invalid IFLA_INET6_STATS value")?,
            )),
            IFLA_INET6_ICMP6STATS => IcmpStats(
                LinkIcmp6StatsBuffer::new(payload)
                    .parse()
                    .context("invalid IFLA_INET6_ICMP6STATS value")?,
            ),
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
