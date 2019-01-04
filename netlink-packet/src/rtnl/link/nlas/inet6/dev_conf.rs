use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

const FORWARDING: Field = 0..4;
const HOPLIMIT: Field = 4..8;
const MTU6: Field = 8..12;
const ACCEPT_RA: Field = 12..16;
const ACCEPT_REDIRECTS: Field = 16..20;
const AUTOCONF: Field = 20..24;
const DAD_TRANSMITS: Field = 24..28;
const RTR_SOLICITS: Field = 28..32;
const RTR_SOLICIT_INTERVAL: Field = 32..36;
const RTR_SOLICIT_DELAY: Field = 36..40;
const USE_TEMPADDR: Field = 40..44;
const TEMP_VALID_LFT: Field = 44..48;
const TEMP_PREFERED_LFT: Field = 48..52;
const REGEN_MAX_RETRY: Field = 52..56;
const MAX_DESYNC_FACTOR: Field = 56..60;
const MAX_ADDRESSES: Field = 60..64;
const FORCE_MLD_VERSION: Field = 64..68;
const ACCEPT_RA_DEFRTR: Field = 68..72;
const ACCEPT_RA_PINFO: Field = 72..76;
const ACCEPT_RA_RTR_PREF: Field = 76..80;
const RTR_PROBE_INTERVAL: Field = 80..84;
const ACCEPT_RA_RT_INFO_MAX_PLEN: Field = 84..88;
const PROXY_NDP: Field = 88..92;
const OPTIMISTIC_DAD: Field = 92..96;
const ACCEPT_SOURCE_ROUTE: Field = 96..100;
const MC_FORWARDING: Field = 100..104;
const DISABLE_IPV6: Field = 104..108;
const ACCEPT_DAD: Field = 108..112;
const FORCE_TLLAO: Field = 112..116;
const NDISC_NOTIFY: Field = 116..120;
const MLDV1_UNSOLICITED_REPORT_INTERVAL: Field = 120..124;
const MLDV2_UNSOLICITED_REPORT_INTERVAL: Field = 124..128;
const SUPPRESS_FRAG_NDISC: Field = 128..132;
const ACCEPT_RA_FROM_LOCAL: Field = 132..136;
const USE_OPTIMISTIC: Field = 136..140;
const ACCEPT_RA_MTU: Field = 140..144;
const STABLE_SECRET: Field = 144..148;
const USE_OIF_ADDRS_ONLY: Field = 148..152;
const ACCEPT_RA_MIN_HOP_LIMIT: Field = 152..156;
const IGNORE_ROUTES_WITH_LINKDOWN: Field = 156..160;
const DROP_UNICAST_IN_L2_MULTICAST: Field = 160..164;
const DROP_UNSOLICITED_NA: Field = 164..168;
const KEEP_ADDR_ON_DOWN: Field = 168..172;
const RTR_SOLICIT_MAX_INTERVAL: Field = 172..176;
const SEG6_ENABLED: Field = 176..180;
const SEG6_REQUIRE_HMAC: Field = 180..184;
const ENHANCED_DAD: Field = 184..188;
const ADDR_GEN_MODE: Field = 188..192;
const DISABLE_POLICY: Field = 192..196;
const ACCEPT_RA_RT_INFO_MIN_PLEN: Field = 196..200;
const NDISC_TCLASS: Field = 200..204;
pub const LINK_INET6_DEV_CONF_LEN: usize = NDISC_TCLASS.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkInet6DevConfBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkInet6DevConfBuffer<T> {
    pub fn new(buffer: T) -> LinkInet6DevConfBuffer<T> {
        LinkInet6DevConfBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<LinkInet6DevConfBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_INET6_DEV_CONF_LEN {
            return Err(format!(
                "invalid LinkInet6DevConfBuffer buffer: length is {} instead of {}",
                len, LINK_INET6_DEV_CONF_LEN
            )
            .into());
        }
        Ok(())
    }
    pub fn forwarding(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[FORWARDING])
    }

    pub fn hoplimit(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[HOPLIMIT])
    }

    pub fn mtu6(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MTU6])
    }

    pub fn accept_ra(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA])
    }

    pub fn accept_redirects(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_REDIRECTS])
    }

    pub fn autoconf(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[AUTOCONF])
    }

    pub fn dad_transmits(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[DAD_TRANSMITS])
    }

    pub fn rtr_solicits(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[RTR_SOLICITS])
    }

    pub fn rtr_solicit_interval(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[RTR_SOLICIT_INTERVAL])
    }

    pub fn rtr_solicit_delay(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[RTR_SOLICIT_DELAY])
    }

    pub fn use_tempaddr(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[USE_TEMPADDR])
    }

    pub fn temp_valid_lft(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[TEMP_VALID_LFT])
    }

    pub fn temp_prefered_lft(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[TEMP_PREFERED_LFT])
    }

    pub fn regen_max_retry(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[REGEN_MAX_RETRY])
    }

    pub fn max_desync_factor(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MAX_DESYNC_FACTOR])
    }

    pub fn max_addresses(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MAX_ADDRESSES])
    }

    pub fn force_mld_version(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[FORCE_MLD_VERSION])
    }

    pub fn accept_ra_defrtr(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_DEFRTR])
    }

    pub fn accept_ra_pinfo(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_PINFO])
    }

    pub fn accept_ra_rtr_pref(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_RTR_PREF])
    }

    pub fn rtr_probe_interval(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[RTR_PROBE_INTERVAL])
    }

    pub fn accept_ra_rt_info_max_plen(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_RT_INFO_MAX_PLEN])
    }

    pub fn proxy_ndp(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[PROXY_NDP])
    }

    pub fn optimistic_dad(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[OPTIMISTIC_DAD])
    }

    pub fn accept_source_route(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_SOURCE_ROUTE])
    }

    pub fn mc_forwarding(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MC_FORWARDING])
    }

    pub fn disable_ipv6(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[DISABLE_IPV6])
    }

    pub fn accept_dad(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_DAD])
    }

    pub fn force_tllao(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[FORCE_TLLAO])
    }

    pub fn ndisc_notify(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[NDISC_NOTIFY])
    }

    pub fn mldv1_unsolicited_report_interval(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MLDV1_UNSOLICITED_REPORT_INTERVAL])
    }

    pub fn mldv2_unsolicited_report_interval(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MLDV2_UNSOLICITED_REPORT_INTERVAL])
    }

    pub fn suppress_frag_ndisc(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[SUPPRESS_FRAG_NDISC])
    }

    pub fn accept_ra_from_local(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_FROM_LOCAL])
    }

    pub fn use_optimistic(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[USE_OPTIMISTIC])
    }

    pub fn accept_ra_mtu(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_MTU])
    }

    pub fn stable_secret(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[STABLE_SECRET])
    }

    pub fn use_oif_addrs_only(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[USE_OIF_ADDRS_ONLY])
    }

    pub fn accept_ra_min_hop_limit(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_MIN_HOP_LIMIT])
    }

    pub fn ignore_routes_with_linkdown(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[IGNORE_ROUTES_WITH_LINKDOWN])
    }

    pub fn drop_unicast_in_l2_multicast(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[DROP_UNICAST_IN_L2_MULTICAST])
    }

    pub fn drop_unsolicited_na(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[DROP_UNSOLICITED_NA])
    }

    pub fn keep_addr_on_down(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[KEEP_ADDR_ON_DOWN])
    }

    pub fn rtr_solicit_max_interval(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[RTR_SOLICIT_MAX_INTERVAL])
    }

    pub fn seg6_enabled(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[SEG6_ENABLED])
    }

    pub fn seg6_require_hmac(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[SEG6_REQUIRE_HMAC])
    }

    pub fn enhanced_dad(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ENHANCED_DAD])
    }

    pub fn addr_gen_mode(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ADDR_GEN_MODE])
    }

    pub fn disable_policy(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[DISABLE_POLICY])
    }

    pub fn accept_ra_rt_info_min_plen(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_RA_RT_INFO_MIN_PLEN])
    }

    pub fn ndisc_tclass(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[NDISC_TCLASS])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkInet6DevConfBuffer<T> {
    pub fn set_forwarding(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[FORWARDING], value.into())
    }

    pub fn set_hoplimit(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[HOPLIMIT], value.into())
    }

    pub fn set_mtu6(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[MTU6], value.into())
    }

    pub fn set_accept_ra(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_RA], value.into())
    }

    pub fn set_accept_redirects(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_REDIRECTS], value.into())
    }

    pub fn set_autoconf(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[AUTOCONF], value.into())
    }

    pub fn set_dad_transmits(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[DAD_TRANSMITS], value.into())
    }

    pub fn set_rtr_solicits(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[RTR_SOLICITS], value.into())
    }

    pub fn set_rtr_solicit_interval(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[RTR_SOLICIT_INTERVAL],
            value.into(),
        )
    }

    pub fn set_rtr_solicit_delay(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[RTR_SOLICIT_DELAY], value.into())
    }

    pub fn set_use_tempaddr(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[USE_TEMPADDR], value.into())
    }

    pub fn set_temp_valid_lft(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[TEMP_VALID_LFT], value.into())
    }

    pub fn set_temp_prefered_lft(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[TEMP_PREFERED_LFT], value.into())
    }

    pub fn set_regen_max_retry(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[REGEN_MAX_RETRY], value.into())
    }

    pub fn set_max_desync_factor(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[MAX_DESYNC_FACTOR], value.into())
    }

    pub fn set_max_addresses(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[MAX_ADDRESSES], value.into())
    }

    pub fn set_force_mld_version(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[FORCE_MLD_VERSION], value.into())
    }

    pub fn set_accept_ra_defrtr(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_RA_DEFRTR], value.into())
    }

    pub fn set_accept_ra_pinfo(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_RA_PINFO], value.into())
    }

    pub fn set_accept_ra_rtr_pref(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_RA_RTR_PREF], value.into())
    }

    pub fn set_rtr_probe_interval(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[RTR_PROBE_INTERVAL], value.into())
    }

    pub fn set_accept_ra_rt_info_max_plen(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[ACCEPT_RA_RT_INFO_MAX_PLEN],
            value.into(),
        )
    }

    pub fn set_proxy_ndp(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[PROXY_NDP], value.into())
    }

    pub fn set_optimistic_dad(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[OPTIMISTIC_DAD], value.into())
    }

    pub fn set_accept_source_route(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_SOURCE_ROUTE], value.into())
    }

    pub fn set_mc_forwarding(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[MC_FORWARDING], value.into())
    }

    pub fn set_disable_ipv6(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[DISABLE_IPV6], value.into())
    }

    pub fn set_accept_dad(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_DAD], value.into())
    }

    pub fn set_force_tllao(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[FORCE_TLLAO], value.into())
    }

    pub fn set_ndisc_notify(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[NDISC_NOTIFY], value.into())
    }

    pub fn set_mldv1_unsolicited_report_interval(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[MLDV1_UNSOLICITED_REPORT_INTERVAL],
            value.into(),
        )
    }

    pub fn set_mldv2_unsolicited_report_interval(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[MLDV2_UNSOLICITED_REPORT_INTERVAL],
            value.into(),
        )
    }

    pub fn set_suppress_frag_ndisc(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[SUPPRESS_FRAG_NDISC], value.into())
    }

    pub fn set_accept_ra_from_local(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[ACCEPT_RA_FROM_LOCAL],
            value.into(),
        )
    }

    pub fn set_use_optimistic(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[USE_OPTIMISTIC], value.into())
    }

    pub fn set_accept_ra_mtu(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_RA_MTU], value.into())
    }

    pub fn set_stable_secret(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[STABLE_SECRET], value.into())
    }

    pub fn set_use_oif_addrs_only(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[USE_OIF_ADDRS_ONLY], value.into())
    }

    pub fn set_accept_ra_min_hop_limit(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[ACCEPT_RA_MIN_HOP_LIMIT],
            value.into(),
        )
    }

    pub fn set_ignore_routes_with_linkdown(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[IGNORE_ROUTES_WITH_LINKDOWN],
            value.into(),
        )
    }

    pub fn set_drop_unicast_in_l2_multicast(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[DROP_UNICAST_IN_L2_MULTICAST],
            value.into(),
        )
    }

    pub fn set_drop_unsolicited_na(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[DROP_UNSOLICITED_NA], value.into())
    }

    pub fn set_keep_addr_on_down(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[KEEP_ADDR_ON_DOWN], value.into())
    }

    pub fn set_rtr_solicit_max_interval(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[RTR_SOLICIT_MAX_INTERVAL],
            value.into(),
        )
    }

    pub fn set_seg6_enabled(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[SEG6_ENABLED], value.into())
    }

    pub fn set_seg6_require_hmac(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[SEG6_REQUIRE_HMAC], value.into())
    }

    pub fn set_enhanced_dad(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ENHANCED_DAD], value.into())
    }

    pub fn set_addr_gen_mode(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ADDR_GEN_MODE], value.into())
    }

    pub fn set_disable_policy(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[DISABLE_POLICY], value.into())
    }

    pub fn set_accept_ra_rt_info_min_plen(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[ACCEPT_RA_RT_INFO_MIN_PLEN],
            value.into(),
        )
    }

    pub fn set_ndisc_tclass(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[NDISC_TCLASS], value.into())
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkInet6DevConf> for LinkInet6DevConfBuffer<T> {
    fn parse(&self) -> Result<LinkInet6DevConf, DecodeError> {
        self.check_buffer_length()?;
        Ok(LinkInet6DevConf {
            forwarding: self.forwarding(),
            hoplimit: self.hoplimit(),
            mtu6: self.mtu6(),
            accept_ra: self.accept_ra(),
            accept_redirects: self.accept_redirects(),
            autoconf: self.autoconf(),
            dad_transmits: self.dad_transmits(),
            rtr_solicits: self.rtr_solicits(),
            rtr_solicit_interval: self.rtr_solicit_interval(),
            rtr_solicit_delay: self.rtr_solicit_delay(),
            use_tempaddr: self.use_tempaddr(),
            temp_valid_lft: self.temp_valid_lft(),
            temp_prefered_lft: self.temp_prefered_lft(),
            regen_max_retry: self.regen_max_retry(),
            max_desync_factor: self.max_desync_factor(),
            max_addresses: self.max_addresses(),
            force_mld_version: self.force_mld_version(),
            accept_ra_defrtr: self.accept_ra_defrtr(),
            accept_ra_pinfo: self.accept_ra_pinfo(),
            accept_ra_rtr_pref: self.accept_ra_rtr_pref(),
            rtr_probe_interval: self.rtr_probe_interval(),
            accept_ra_rt_info_max_plen: self.accept_ra_rt_info_max_plen(),
            proxy_ndp: self.proxy_ndp(),
            optimistic_dad: self.optimistic_dad(),
            accept_source_route: self.accept_source_route(),
            mc_forwarding: self.mc_forwarding(),
            disable_ipv6: self.disable_ipv6(),
            accept_dad: self.accept_dad(),
            force_tllao: self.force_tllao(),
            ndisc_notify: self.ndisc_notify(),
            mldv1_unsolicited_report_interval: self.mldv1_unsolicited_report_interval(),
            mldv2_unsolicited_report_interval: self.mldv2_unsolicited_report_interval(),
            suppress_frag_ndisc: self.suppress_frag_ndisc(),
            accept_ra_from_local: self.accept_ra_from_local(),
            use_optimistic: self.use_optimistic(),
            accept_ra_mtu: self.accept_ra_mtu(),
            stable_secret: self.stable_secret(),
            use_oif_addrs_only: self.use_oif_addrs_only(),
            accept_ra_min_hop_limit: self.accept_ra_min_hop_limit(),
            ignore_routes_with_linkdown: self.ignore_routes_with_linkdown(),
            drop_unicast_in_l2_multicast: self.drop_unicast_in_l2_multicast(),
            drop_unsolicited_na: self.drop_unsolicited_na(),
            keep_addr_on_down: self.keep_addr_on_down(),
            rtr_solicit_max_interval: self.rtr_solicit_max_interval(),
            seg6_enabled: self.seg6_enabled(),
            seg6_require_hmac: self.seg6_require_hmac(),
            enhanced_dad: self.enhanced_dad(),
            addr_gen_mode: self.addr_gen_mode(),
            disable_policy: self.disable_policy(),
            accept_ra_rt_info_min_plen: self.accept_ra_rt_info_min_plen(),
            ndisc_tclass: self.ndisc_tclass(),
        })
    }
}

impl Emitable for LinkInet6DevConf {
    fn buffer_len(&self) -> usize {
        LINK_INET6_DEV_CONF_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkInet6DevConfBuffer::new(buffer);
        buffer.set_forwarding(self.forwarding);
        buffer.set_hoplimit(self.hoplimit);
        buffer.set_mtu6(self.mtu6);
        buffer.set_accept_ra(self.accept_ra);
        buffer.set_accept_redirects(self.accept_redirects);
        buffer.set_autoconf(self.autoconf);
        buffer.set_dad_transmits(self.dad_transmits);
        buffer.set_rtr_solicits(self.rtr_solicits);
        buffer.set_rtr_solicit_interval(self.rtr_solicit_interval);
        buffer.set_rtr_solicit_delay(self.rtr_solicit_delay);
        buffer.set_use_tempaddr(self.use_tempaddr);
        buffer.set_temp_valid_lft(self.temp_valid_lft);
        buffer.set_temp_prefered_lft(self.temp_prefered_lft);
        buffer.set_regen_max_retry(self.regen_max_retry);
        buffer.set_max_desync_factor(self.max_desync_factor);
        buffer.set_max_addresses(self.max_addresses);
        buffer.set_force_mld_version(self.force_mld_version);
        buffer.set_accept_ra_defrtr(self.accept_ra_defrtr);
        buffer.set_accept_ra_pinfo(self.accept_ra_pinfo);
        buffer.set_accept_ra_rtr_pref(self.accept_ra_rtr_pref);
        buffer.set_rtr_probe_interval(self.rtr_probe_interval);
        buffer.set_accept_ra_rt_info_max_plen(self.accept_ra_rt_info_max_plen);
        buffer.set_proxy_ndp(self.proxy_ndp);
        buffer.set_optimistic_dad(self.optimistic_dad);
        buffer.set_accept_source_route(self.accept_source_route);
        buffer.set_mc_forwarding(self.mc_forwarding);
        buffer.set_disable_ipv6(self.disable_ipv6);
        buffer.set_accept_dad(self.accept_dad);
        buffer.set_force_tllao(self.force_tllao);
        buffer.set_ndisc_notify(self.ndisc_notify);
        buffer.set_mldv1_unsolicited_report_interval(self.mldv1_unsolicited_report_interval);
        buffer.set_mldv2_unsolicited_report_interval(self.mldv2_unsolicited_report_interval);
        buffer.set_suppress_frag_ndisc(self.suppress_frag_ndisc);
        buffer.set_accept_ra_from_local(self.accept_ra_from_local);
        buffer.set_use_optimistic(self.use_optimistic);
        buffer.set_accept_ra_mtu(self.accept_ra_mtu);
        buffer.set_stable_secret(self.stable_secret);
        buffer.set_use_oif_addrs_only(self.use_oif_addrs_only);
        buffer.set_accept_ra_min_hop_limit(self.accept_ra_min_hop_limit);
        buffer.set_ignore_routes_with_linkdown(self.ignore_routes_with_linkdown);
        buffer.set_drop_unicast_in_l2_multicast(self.drop_unicast_in_l2_multicast);
        buffer.set_drop_unsolicited_na(self.drop_unsolicited_na);
        buffer.set_keep_addr_on_down(self.keep_addr_on_down);
        buffer.set_rtr_solicit_max_interval(self.rtr_solicit_max_interval);
        buffer.set_seg6_enabled(self.seg6_enabled);
        buffer.set_seg6_require_hmac(self.seg6_require_hmac);
        buffer.set_enhanced_dad(self.enhanced_dad);
        buffer.set_addr_gen_mode(self.addr_gen_mode);
        buffer.set_disable_policy(self.disable_policy);
        buffer.set_accept_ra_rt_info_min_plen(self.accept_ra_rt_info_min_plen);
        buffer.set_ndisc_tclass(self.ndisc_tclass);
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
