use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::constants::*;

use crate::utils::{parse_ipv6, parse_u32, parse_u8};
use crate::{DecodeError, DefaultNla, Nla, NlaBuffer, Parseable};

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

const LINK_INET6_STATS_LEN: usize = 36 * 4;

impl LinkInet6Stats {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < LINK_INET6_STATS_LEN {
            return Err(DecodeError::from(format!(
                "LinkInet6Stats is {} bytes, buffer is only {} bytes: {:#x?}",
                LINK_INET6_STATS_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(LinkInet6Stats {
            num: NativeEndian::read_i64(&buf[0..8]),
            in_pkts: NativeEndian::read_i64(&buf[8..16]),
            in_octets: NativeEndian::read_i64(&buf[16..24]),
            in_delivers: NativeEndian::read_i64(&buf[24..32]),
            out_forw_datagrams: NativeEndian::read_i64(&buf[32..40]),
            out_pkts: NativeEndian::read_i64(&buf[40..48]),
            out_octets: NativeEndian::read_i64(&buf[48..56]),
            in_hdr_errors: NativeEndian::read_i64(&buf[56..64]),
            in_too_big_errors: NativeEndian::read_i64(&buf[64..72]),
            in_no_routes: NativeEndian::read_i64(&buf[72..80]),
            in_addr_errors: NativeEndian::read_i64(&buf[80..88]),
            in_unknown_protos: NativeEndian::read_i64(&buf[88..96]),
            in_truncated_pkts: NativeEndian::read_i64(&buf[96..104]),
            in_discards: NativeEndian::read_i64(&buf[104..112]),
            out_discards: NativeEndian::read_i64(&buf[112..120]),
            out_no_routes: NativeEndian::read_i64(&buf[120..128]),
            reasm_timeout: NativeEndian::read_i64(&buf[128..136]),
            reasm_reqds: NativeEndian::read_i64(&buf[136..144]),
            reasm_oks: NativeEndian::read_i64(&buf[144..152]),
            reasm_fails: NativeEndian::read_i64(&buf[152..160]),
            frag_oks: NativeEndian::read_i64(&buf[160..168]),
            frag_fails: NativeEndian::read_i64(&buf[168..176]),
            frag_creates: NativeEndian::read_i64(&buf[176..184]),
            in_mcast_pkts: NativeEndian::read_i64(&buf[184..192]),
            out_mcast_pkts: NativeEndian::read_i64(&buf[192..200]),
            in_bcast_pkts: NativeEndian::read_i64(&buf[200..208]),
            out_bcast_pkts: NativeEndian::read_i64(&buf[208..216]),
            in_mcast_octets: NativeEndian::read_i64(&buf[216..224]),
            out_mcast_octets: NativeEndian::read_i64(&buf[224..232]),
            in_bcast_octets: NativeEndian::read_i64(&buf[232..240]),
            out_bcast_octets: NativeEndian::read_i64(&buf[240..248]),
            in_csum_errors: NativeEndian::read_i64(&buf[248..256]),
            in_no_ect_pkts: NativeEndian::read_i64(&buf[256..264]),
            in_ect1_pkts: NativeEndian::read_i64(&buf[264..272]),
            in_ect0_pkts: NativeEndian::read_i64(&buf[272..280]),
            in_ce_pkts: NativeEndian::read_i64(&buf[280..288]),
        })
    }
    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < LINK_INET6_STATS_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but LinkInet6Stats is {} bytes",
                buf.len(),
                LINK_INET6_STATS_LEN
            )));
        }
        NativeEndian::write_i64(&mut buf[0..8], self.num);
        NativeEndian::write_i64(&mut buf[8..16], self.in_pkts);
        NativeEndian::write_i64(&mut buf[16..24], self.in_octets);
        NativeEndian::write_i64(&mut buf[24..32], self.in_delivers);
        NativeEndian::write_i64(&mut buf[32..40], self.out_forw_datagrams);
        NativeEndian::write_i64(&mut buf[40..48], self.out_pkts);
        NativeEndian::write_i64(&mut buf[48..56], self.out_octets);
        NativeEndian::write_i64(&mut buf[56..64], self.in_hdr_errors);
        NativeEndian::write_i64(&mut buf[64..72], self.in_too_big_errors);
        NativeEndian::write_i64(&mut buf[72..80], self.in_no_routes);
        NativeEndian::write_i64(&mut buf[80..88], self.in_addr_errors);
        NativeEndian::write_i64(&mut buf[88..96], self.in_unknown_protos);
        NativeEndian::write_i64(&mut buf[96..104], self.in_truncated_pkts);
        NativeEndian::write_i64(&mut buf[104..112], self.in_discards);
        NativeEndian::write_i64(&mut buf[112..120], self.out_discards);
        NativeEndian::write_i64(&mut buf[120..128], self.out_no_routes);
        NativeEndian::write_i64(&mut buf[128..136], self.reasm_timeout);
        NativeEndian::write_i64(&mut buf[136..144], self.reasm_reqds);
        NativeEndian::write_i64(&mut buf[144..152], self.reasm_oks);
        NativeEndian::write_i64(&mut buf[152..160], self.reasm_fails);
        NativeEndian::write_i64(&mut buf[160..168], self.frag_oks);
        NativeEndian::write_i64(&mut buf[168..176], self.frag_fails);
        NativeEndian::write_i64(&mut buf[176..184], self.frag_creates);
        NativeEndian::write_i64(&mut buf[184..192], self.in_mcast_pkts);
        NativeEndian::write_i64(&mut buf[192..200], self.out_mcast_pkts);
        NativeEndian::write_i64(&mut buf[200..208], self.in_bcast_pkts);
        NativeEndian::write_i64(&mut buf[208..216], self.out_bcast_pkts);
        NativeEndian::write_i64(&mut buf[216..224], self.in_mcast_octets);
        NativeEndian::write_i64(&mut buf[224..232], self.out_mcast_octets);
        NativeEndian::write_i64(&mut buf[232..240], self.in_bcast_octets);
        NativeEndian::write_i64(&mut buf[240..248], self.out_bcast_octets);
        NativeEndian::write_i64(&mut buf[248..256], self.in_csum_errors);
        NativeEndian::write_i64(&mut buf[256..264], self.in_no_ect_pkts);
        NativeEndian::write_i64(&mut buf[264..272], self.in_ect1_pkts);
        NativeEndian::write_i64(&mut buf[272..280], self.in_ect0_pkts);
        NativeEndian::write_i64(&mut buf[280..288], self.in_ce_pkts);
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkIcmp6Stats {
    pub num: i64,
    pub in_msgs: i64,
    pub in_errors: i64,
    pub out_msgs: i64,
    pub out_errors: i64,
    pub csum_errors: i64,
}

const LINK_ICMP6_STATS_LEN: usize = 6 * 8;

impl LinkIcmp6Stats {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < LINK_ICMP6_STATS_LEN {
            return Err(DecodeError::from(format!(
                "LinkIcmp6Stats is {} bytes, buffer is only {} bytes: {:#x?}",
                LINK_ICMP6_STATS_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(LinkIcmp6Stats {
            num: NativeEndian::read_i64(&buf[0..8]),
            in_msgs: NativeEndian::read_i64(&buf[8..16]),
            in_errors: NativeEndian::read_i64(&buf[16..24]),
            out_msgs: NativeEndian::read_i64(&buf[24..32]),
            out_errors: NativeEndian::read_i64(&buf[32..40]),
            csum_errors: NativeEndian::read_i64(&buf[40..48]),
        })
    }
    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < LINK_ICMP6_STATS_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but LinkIcmp6Stats is {} bytes",
                buf.len(),
                LINK_ICMP6_STATS_LEN
            )));
        }
        NativeEndian::write_i64(&mut buf[0..8], self.num);
        NativeEndian::write_i64(&mut buf[8..16], self.in_msgs);
        NativeEndian::write_i64(&mut buf[16..24], self.in_errors);
        NativeEndian::write_i64(&mut buf[24..32], self.out_msgs);
        NativeEndian::write_i64(&mut buf[32..40], self.out_errors);
        NativeEndian::write_i64(&mut buf[40..48], self.csum_errors);
        Ok(())
    }
}

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
const LINK_INET6_DEV_CONF_LEN: usize = 50 * 4;

impl LinkInet6DevConf {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < LINK_INET6_DEV_CONF_LEN {
            return Err(DecodeError::from(format!(
                "LinkInet6DevConf is {} bytes, buffer is only {} bytes: {:#x?}",
                LINK_INET6_DEV_CONF_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(LinkInet6DevConf {
            forwarding: NativeEndian::read_i32(&buf[0..4]),
            hoplimit: NativeEndian::read_i32(&buf[4..8]),
            mtu6: NativeEndian::read_i32(&buf[8..12]),
            accept_ra: NativeEndian::read_i32(&buf[12..16]),
            accept_redirects: NativeEndian::read_i32(&buf[16..20]),
            autoconf: NativeEndian::read_i32(&buf[20..24]),
            dad_transmits: NativeEndian::read_i32(&buf[24..28]),
            rtr_solicits: NativeEndian::read_i32(&buf[28..32]),
            rtr_solicit_interval: NativeEndian::read_i32(&buf[32..36]),
            rtr_solicit_delay: NativeEndian::read_i32(&buf[36..40]),
            use_tempaddr: NativeEndian::read_i32(&buf[40..44]),
            temp_valid_lft: NativeEndian::read_i32(&buf[44..48]),
            temp_prefered_lft: NativeEndian::read_i32(&buf[48..52]),
            regen_max_retry: NativeEndian::read_i32(&buf[52..56]),
            max_desync_factor: NativeEndian::read_i32(&buf[56..60]),
            max_addresses: NativeEndian::read_i32(&buf[60..64]),
            force_mld_version: NativeEndian::read_i32(&buf[64..68]),
            accept_ra_defrtr: NativeEndian::read_i32(&buf[68..72]),
            accept_ra_pinfo: NativeEndian::read_i32(&buf[72..76]),
            accept_ra_rtr_pref: NativeEndian::read_i32(&buf[76..80]),
            rtr_probe_interval: NativeEndian::read_i32(&buf[80..84]),
            accept_ra_rt_info_max_plen: NativeEndian::read_i32(&buf[84..88]),
            proxy_ndp: NativeEndian::read_i32(&buf[88..92]),
            optimistic_dad: NativeEndian::read_i32(&buf[92..96]),
            accept_source_route: NativeEndian::read_i32(&buf[96..100]),
            mc_forwarding: NativeEndian::read_i32(&buf[100..104]),
            disable_ipv6: NativeEndian::read_i32(&buf[104..108]),
            accept_dad: NativeEndian::read_i32(&buf[108..112]),
            force_tllao: NativeEndian::read_i32(&buf[112..116]),
            ndisc_notify: NativeEndian::read_i32(&buf[116..120]),
            mldv1_unsolicited_report_interval: NativeEndian::read_i32(&buf[120..124]),
            mldv2_unsolicited_report_interval: NativeEndian::read_i32(&buf[124..128]),
            suppress_frag_ndisc: NativeEndian::read_i32(&buf[128..132]),
            accept_ra_from_local: NativeEndian::read_i32(&buf[132..136]),
            use_optimistic: NativeEndian::read_i32(&buf[136..140]),
            accept_ra_mtu: NativeEndian::read_i32(&buf[140..144]),
            stable_secret: NativeEndian::read_i32(&buf[144..148]),
            use_oif_addrs_only: NativeEndian::read_i32(&buf[148..152]),
            accept_ra_min_hop_limit: NativeEndian::read_i32(&buf[152..156]),
            ignore_routes_with_linkdown: NativeEndian::read_i32(&buf[156..160]),
            drop_unicast_in_l2_multicast: NativeEndian::read_i32(&buf[160..164]),
            drop_unsolicited_na: NativeEndian::read_i32(&buf[164..168]),
            keep_addr_on_down: NativeEndian::read_i32(&buf[168..172]),
            rtr_solicit_max_interval: NativeEndian::read_i32(&buf[172..176]),
            seg6_enabled: NativeEndian::read_i32(&buf[176..180]),
            seg6_require_hmac: NativeEndian::read_i32(&buf[180..184]),
            enhanced_dad: NativeEndian::read_i32(&buf[184..188]),
            addr_gen_mode: NativeEndian::read_i32(&buf[188..192]),
            disable_policy: NativeEndian::read_i32(&buf[192..196]),
            accept_ra_rt_info_min_plen: NativeEndian::read_i32(&buf[196..200]),
            ndisc_tclass: NativeEndian::read_i32(&buf[200..204]),
        })
    }
    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < LINK_INET6_DEV_CONF_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but LinkInet6DevConf is {} bytes",
                buf.len(),
                LINK_INET6_DEV_CONF_LEN
            )));
        }
        NativeEndian::write_i32(&mut buf[0..4], self.forwarding);
        NativeEndian::write_i32(&mut buf[4..8], self.hoplimit);
        NativeEndian::write_i32(&mut buf[8..12], self.mtu6);
        NativeEndian::write_i32(&mut buf[12..16], self.accept_ra);
        NativeEndian::write_i32(&mut buf[16..20], self.accept_redirects);
        NativeEndian::write_i32(&mut buf[20..24], self.autoconf);
        NativeEndian::write_i32(&mut buf[24..28], self.dad_transmits);
        NativeEndian::write_i32(&mut buf[28..32], self.rtr_solicits);
        NativeEndian::write_i32(&mut buf[32..36], self.rtr_solicit_interval);
        NativeEndian::write_i32(&mut buf[36..40], self.rtr_solicit_delay);
        NativeEndian::write_i32(&mut buf[40..44], self.use_tempaddr);
        NativeEndian::write_i32(&mut buf[44..48], self.temp_valid_lft);
        NativeEndian::write_i32(&mut buf[48..52], self.temp_prefered_lft);
        NativeEndian::write_i32(&mut buf[52..56], self.regen_max_retry);
        NativeEndian::write_i32(&mut buf[56..60], self.max_desync_factor);
        NativeEndian::write_i32(&mut buf[60..64], self.max_addresses);
        NativeEndian::write_i32(&mut buf[64..68], self.force_mld_version);
        NativeEndian::write_i32(&mut buf[68..72], self.accept_ra_defrtr);
        NativeEndian::write_i32(&mut buf[72..76], self.accept_ra_pinfo);
        NativeEndian::write_i32(&mut buf[76..80], self.accept_ra_rtr_pref);
        NativeEndian::write_i32(&mut buf[80..84], self.rtr_probe_interval);
        NativeEndian::write_i32(&mut buf[84..88], self.accept_ra_rt_info_max_plen);
        NativeEndian::write_i32(&mut buf[88..92], self.proxy_ndp);
        NativeEndian::write_i32(&mut buf[92..96], self.optimistic_dad);
        NativeEndian::write_i32(&mut buf[96..100], self.accept_source_route);
        NativeEndian::write_i32(&mut buf[100..104], self.mc_forwarding);
        NativeEndian::write_i32(&mut buf[104..108], self.disable_ipv6);
        NativeEndian::write_i32(&mut buf[108..112], self.accept_dad);
        NativeEndian::write_i32(&mut buf[112..116], self.force_tllao);
        NativeEndian::write_i32(&mut buf[116..120], self.ndisc_notify);
        NativeEndian::write_i32(&mut buf[120..124], self.mldv1_unsolicited_report_interval);
        NativeEndian::write_i32(&mut buf[124..128], self.mldv2_unsolicited_report_interval);
        NativeEndian::write_i32(&mut buf[128..132], self.suppress_frag_ndisc);
        NativeEndian::write_i32(&mut buf[132..136], self.accept_ra_from_local);
        NativeEndian::write_i32(&mut buf[136..140], self.use_optimistic);
        NativeEndian::write_i32(&mut buf[140..144], self.accept_ra_mtu);
        NativeEndian::write_i32(&mut buf[144..148], self.stable_secret);
        NativeEndian::write_i32(&mut buf[148..152], self.use_oif_addrs_only);
        NativeEndian::write_i32(&mut buf[152..156], self.accept_ra_min_hop_limit);
        NativeEndian::write_i32(&mut buf[156..160], self.ignore_routes_with_linkdown);
        NativeEndian::write_i32(&mut buf[160..164], self.drop_unicast_in_l2_multicast);
        NativeEndian::write_i32(&mut buf[164..168], self.drop_unsolicited_na);
        NativeEndian::write_i32(&mut buf[168..172], self.keep_addr_on_down);
        NativeEndian::write_i32(&mut buf[172..176], self.rtr_solicit_max_interval);
        NativeEndian::write_i32(&mut buf[176..180], self.seg6_enabled);
        NativeEndian::write_i32(&mut buf[180..184], self.seg6_require_hmac);
        NativeEndian::write_i32(&mut buf[184..188], self.enhanced_dad);
        NativeEndian::write_i32(&mut buf[188..192], self.addr_gen_mode);
        NativeEndian::write_i32(&mut buf[192..196], self.disable_policy);
        NativeEndian::write_i32(&mut buf[196..200], self.accept_ra_rt_info_min_plen);
        NativeEndian::write_i32(&mut buf[200..204], self.ndisc_tclass);
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInet6CacheInfo {
    pub max_reasm_len: i32,
    pub tstamp: i32,
    pub reachable_time: i32,
    pub retrans_time: i32,
}

const LINK_INET6_CACHE_INFO_LEN: usize = 4 * 4;

impl LinkInet6CacheInfo {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < LINK_INET6_CACHE_INFO_LEN {
            return Err(DecodeError::from(format!(
                "LinkInet6CacheInfo is {} bytes, buffer is only {} bytes: {:#x?}",
                LINK_INET6_CACHE_INFO_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(LinkInet6CacheInfo {
            max_reasm_len: NativeEndian::read_i32(&buf[0..4]),
            tstamp: NativeEndian::read_i32(&buf[4..8]),
            reachable_time: NativeEndian::read_i32(&buf[8..12]),
            retrans_time: NativeEndian::read_i32(&buf[12..16]),
        })
    }
    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < LINK_INET6_CACHE_INFO_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but LinkInet6CacheInfo is {} bytes",
                buf.len(),
                LINK_INET6_CACHE_INFO_LEN
            )));
        }
        NativeEndian::write_i32(&mut buf[0..4], self.max_reasm_len);
        NativeEndian::write_i32(&mut buf[4..8], self.tstamp);
        NativeEndian::write_i32(&mut buf[8..12], self.reachable_time);
        NativeEndian::write_i32(&mut buf[12..16], self.retrans_time);
        Ok(())
    }
}

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
            CacheInfo(ref cache_info) => cache_info
                .to_bytes(buffer)
                .expect("check the buffer length before calling emit_value()!"),
            DevConf(ref inet6_dev_conf) => inet6_dev_conf
                .to_bytes(buffer)
                .expect("check the buffer length before calling emit_value()!"),
            Stats(ref inet6_stats) => inet6_stats
                .to_bytes(buffer)
                .expect("check the buffer length before calling emit_value()!"),
            IcmpStats(ref icmp6_stats) => icmp6_stats
                .to_bytes(buffer)
                .expect("check the buffer length before calling emit_value()!"),
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
                LinkInet6CacheInfo::from_bytes(payload)
                    .context("invalid IFLA_INET6_CACHEINFO value")?,
            ),
            IFLA_INET6_CONF => DevConf(Box::new(
                LinkInet6DevConf::from_bytes(payload).context("invalid IFLA_INET6_CONF value")?,
            )),
            IFLA_INET6_STATS => Stats(Box::new(
                LinkInet6Stats::from_bytes(payload).context("invalid IFLA_INET6_STATS value")?,
            )),
            IFLA_INET6_ICMP6STATS => IcmpStats(
                LinkIcmp6Stats::from_bytes(payload)
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
