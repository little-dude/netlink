use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};

use constants::*;

use utils::{parse_ipv6, parse_u32, parse_u8};
use {DefaultNla, NativeNla, Nla, NlaBuffer, Parseable, Result};

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInet6Stats {
    pub num: i64,
    pub in_pkts: i64,
    pub in_octets: i64,
    pub in_delivers: i64,
    pub out_forw_datagrams: i64,
    pub out_pkts: i64,
    pub out_octets: i64,
    pub in_hdr_errors: i64,
    pub in_too_big_errors: i64,
    pub in_no_routes: i64,
    pub in_addr_errors: i64,
    pub in_unknown_protos: i64,
    pub in_truncated_pkts: i64,
    pub in_discards: i64,
    pub out_discards: i64,
    pub out_no_routes: i64,
    pub reasm_timeout: i64,
    pub reasm_reqds: i64,
    pub reasm_oks: i64,
    pub reasm_fails: i64,
    pub frag_oks: i64,
    pub frag_fails: i64,
    pub frag_creates: i64,
    pub in_mcast_pkts: i64,
    pub out_mcast_pkts: i64,
    pub in_bcast_pkts: i64,
    pub out_bcast_pkts: i64,
    pub in_mcast_octets: i64,
    pub out_mcast_octets: i64,
    pub in_bcast_octets: i64,
    pub out_bcast_octets: i64,
    pub in_csum_errors: i64,
    pub in_no_ect_pkts: i64,
    pub in_ect1_pkts: i64,
    pub in_ect0_pkts: i64,
    pub in_ce_pkts: i64,
}

impl NativeNla for LinkInet6Stats {}

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkIcmp6Stats {
    pub num: i64,
    pub in_msgs: i64,
    pub in_errors: i64,
    pub out_msgs: i64,
    pub out_errors: i64,
    pub csum_errors: i64,
}

impl NativeNla for LinkIcmp6Stats {}

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInet6DevConf {
    pub forwarding: i32,
    pub hoplimit: i32,
    pub mtu6: i32,
    pub accept_ra: i32,
    pub accept_redirects: i32,
    pub autoconf: i32,
    pub dad_transmits: i32,
    pub rtr_solicits: i32,
    pub rtr_solicit_interval: i32,
    pub rtr_solicit_delay: i32,
    pub use_tempaddr: i32,
    pub temp_valid_lft: i32,
    pub temp_prefered_lft: i32,
    pub regen_max_retry: i32,
    pub max_desync_factor: i32,
    pub max_addresses: i32,
    pub force_mld_version: i32,
    pub accept_ra_defrtr: i32,
    pub accept_ra_pinfo: i32,
    pub accept_ra_rtr_pref: i32,
    pub rtr_probe_interval: i32,
    pub accept_ra_rt_info_max_plen: i32,
    pub proxy_ndp: i32,
    pub optimistic_dad: i32,
    pub accept_source_route: i32,
    pub mc_forwarding: i32,
    pub disable_ipv6: i32,
    pub accept_dad: i32,
    pub force_tllao: i32,
    pub ndisc_notify: i32,
    pub mldv1_unsolicited_report_interval: i32,
    pub mldv2_unsolicited_report_interval: i32,
    pub suppress_frag_ndisc: i32,
    pub accept_ra_from_local: i32,
    pub use_optimistic: i32,
    pub accept_ra_mtu: i32,
    pub stable_secret: i32,
    pub use_oif_addrs_only: i32,
    pub accept_ra_min_hop_limit: i32,
    pub ignore_routes_with_linkdown: i32,
    pub drop_unicast_in_l2_multicast: i32,
    pub drop_unsolicited_na: i32,
    pub keep_addr_on_down: i32,
    pub rtr_solicit_max_interval: i32,
    pub seg6_enabled: i32,
    pub seg6_require_hmac: i32,
    pub enhanced_dad: i32,
    pub addr_gen_mode: i32,
    pub disable_policy: i32,
    pub accept_ra_rt_info_min_plen: i32,
    pub ndisc_tclass: i32,
}

impl NativeNla for LinkInet6DevConf {}

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInet6CacheInfo {
    pub max_reasm_len: i32,
    pub tstamp: i32,
    pub reachable_time: i32,
    pub retrans_time: i32,
}

impl NativeNla for LinkInet6CacheInfo {}

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
            Flags(_) => size_of::<u32>(),
            CacheInfo(_) => size_of::<LinkInet6CacheInfo>(),
            DevConf(_) => size_of::<LinkInet6DevConf>(),
            Stats(_) => size_of::<LinkInet6Stats>(),
            IcmpStats(_) => size_of::<LinkIcmp6Stats>(),
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
            CacheInfo(ref cache_info) => cache_info.to_bytes(buffer),
            DevConf(ref inet6_dev_conf) => inet6_dev_conf.to_bytes(buffer),
            Stats(ref inet6_stats) => inet6_stats.to_bytes(buffer),
            IcmpStats(ref icmp6_stats) => icmp6_stats.to_bytes(buffer),
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
    fn parse(&self) -> Result<LinkAfInet6Nla> {
        use self::LinkAfInet6Nla::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFLA_INET6_UNSPEC => Unspec(payload.to_vec()),
            IFLA_INET6_FLAGS => Flags(parse_u32(payload)?),
            IFLA_INET6_CACHEINFO => CacheInfo(LinkInet6CacheInfo::from_bytes(payload)?),
            IFLA_INET6_CONF => DevConf(Box::new(LinkInet6DevConf::from_bytes(payload)?)),
            IFLA_INET6_STATS => Stats(Box::new(LinkInet6Stats::from_bytes(payload)?)),
            IFLA_INET6_ICMP6STATS => IcmpStats(LinkIcmp6Stats::from_bytes(payload)?),
            IFLA_INET6_TOKEN => Token(parse_ipv6(payload)?),
            IFLA_INET6_ADDR_GEN_MODE => AddrGenMode(parse_u8(payload)?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}
