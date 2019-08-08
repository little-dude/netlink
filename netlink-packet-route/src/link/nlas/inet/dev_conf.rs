use byteorder::{ByteOrder, NativeEndian};

use crate::{
    traits::{Emitable, Parseable},
    DecodeError, Field,
};

const FORWARDING: Field = 0..4;
const MC_FORWARDING: Field = 4..8;
const PROXY_ARP: Field = 8..12;
const ACCEPT_REDIRECTS: Field = 12..16;
const SECURE_REDIRECTS: Field = 16..20;
const SEND_REDIRECTS: Field = 20..24;
const SHARED_MEDIA: Field = 24..28;
const RP_FILTER: Field = 28..32;
const ACCEPT_SOURCE_ROUTE: Field = 32..36;
const BOOTP_RELAY: Field = 36..40;
const LOG_MARTIANS: Field = 40..44;
const TAG: Field = 44..48;
const ARPFILTER: Field = 48..52;
const MEDIUM_ID: Field = 52..56;
const NOXFRM: Field = 56..60;
const NOPOLICY: Field = 60..64;
const FORCE_IGMP_VERSION: Field = 64..68;
const ARP_ANNOUNCE: Field = 68..72;
const ARP_IGNORE: Field = 72..76;
const PROMOTE_SECONDARIES: Field = 76..80;
const ARP_ACCEPT: Field = 80..84;
const ARP_NOTIFY: Field = 84..88;
const ACCEPT_LOCAL: Field = 88..92;
const SRC_VMARK: Field = 92..96;
const PROXY_ARP_PVLAN: Field = 96..100;
const ROUTE_LOCALNET: Field = 100..104;
const IGMPV2_UNSOLICITED_REPORT_INTERVAL: Field = 104..108;
const IGMPV3_UNSOLICITED_REPORT_INTERVAL: Field = 108..112;
const IGNORE_ROUTES_WITH_LINKDOWN: Field = 112..116;
const DROP_UNICAST_IN_L2_MULTICAST: Field = 116..120;
const DROP_GRATUITOUS_ARP: Field = 120..124;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInetDevConf {
    pub forwarding: i32,
    pub mc_forwarding: i32,
    pub proxy_arp: i32,
    pub accept_redirects: i32,
    pub secure_redirects: i32,
    pub send_redirects: i32,
    pub shared_media: i32,
    pub rp_filter: i32,
    pub accept_source_route: i32,
    pub bootp_relay: i32,
    pub log_martians: i32,
    pub tag: i32,
    pub arpfilter: i32,
    pub medium_id: i32,
    pub noxfrm: i32,
    pub nopolicy: i32,
    pub force_igmp_version: i32,
    pub arp_announce: i32,
    pub arp_ignore: i32,
    pub promote_secondaries: i32,
    pub arp_accept: i32,
    pub arp_notify: i32,
    pub accept_local: i32,
    pub src_vmark: i32,
    pub proxy_arp_pvlan: i32,
    pub route_localnet: i32,
    pub igmpv2_unsolicited_report_interval: i32,
    pub igmpv3_unsolicited_report_interval: i32,
    pub ignore_routes_with_linkdown: i32,
    pub drop_unicast_in_l2_multicast: i32,
    pub drop_gratuitous_arp: i32,
}

pub const LINK_INET_DEV_CONF_LEN: usize = DROP_GRATUITOUS_ARP.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkInetDevConfBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkInetDevConfBuffer<T> {
    pub fn new(buffer: T) -> LinkInetDevConfBuffer<T> {
        LinkInetDevConfBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<LinkInetDevConfBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_INET_DEV_CONF_LEN {
            return Err(format!(
                "invalid LinkInetDevConfBuffer buffer: length is {} instead of {}",
                len, LINK_INET_DEV_CONF_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn forwarding(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[FORWARDING])
    }

    pub fn mc_forwarding(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MC_FORWARDING])
    }

    pub fn proxy_arp(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[PROXY_ARP])
    }

    pub fn accept_redirects(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_REDIRECTS])
    }

    pub fn secure_redirects(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[SECURE_REDIRECTS])
    }

    pub fn send_redirects(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[SEND_REDIRECTS])
    }

    pub fn shared_media(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[SHARED_MEDIA])
    }

    pub fn rp_filter(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[RP_FILTER])
    }

    pub fn accept_source_route(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_SOURCE_ROUTE])
    }

    pub fn bootp_relay(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[BOOTP_RELAY])
    }

    pub fn log_martians(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[LOG_MARTIANS])
    }

    pub fn tag(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[TAG])
    }

    pub fn arpfilter(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ARPFILTER])
    }

    pub fn medium_id(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MEDIUM_ID])
    }

    pub fn noxfrm(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[NOXFRM])
    }

    pub fn nopolicy(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[NOPOLICY])
    }

    pub fn force_igmp_version(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[FORCE_IGMP_VERSION])
    }

    pub fn arp_announce(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ARP_ANNOUNCE])
    }

    pub fn arp_ignore(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ARP_IGNORE])
    }

    pub fn promote_secondaries(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[PROMOTE_SECONDARIES])
    }

    pub fn arp_accept(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ARP_ACCEPT])
    }

    pub fn arp_notify(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ARP_NOTIFY])
    }

    pub fn accept_local(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ACCEPT_LOCAL])
    }

    pub fn src_vmark(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[SRC_VMARK])
    }

    pub fn proxy_arp_pvlan(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[PROXY_ARP_PVLAN])
    }

    pub fn route_localnet(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[ROUTE_LOCALNET])
    }

    pub fn igmpv2_unsolicited_report_interval(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[IGMPV2_UNSOLICITED_REPORT_INTERVAL])
    }

    pub fn igmpv3_unsolicited_report_interval(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[IGMPV3_UNSOLICITED_REPORT_INTERVAL])
    }

    pub fn ignore_routes_with_linkdown(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[IGNORE_ROUTES_WITH_LINKDOWN])
    }

    pub fn drop_unicast_in_l2_multicast(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[DROP_UNICAST_IN_L2_MULTICAST])
    }

    pub fn drop_gratuitous_arp(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[DROP_GRATUITOUS_ARP])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkInetDevConfBuffer<T> {
    pub fn set_forwarding(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[FORWARDING], value)
    }

    pub fn set_mc_forwarding(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[MC_FORWARDING], value)
    }

    pub fn set_proxy_arp(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[PROXY_ARP], value)
    }

    pub fn set_accept_redirects(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_REDIRECTS], value)
    }

    pub fn set_secure_redirects(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[SECURE_REDIRECTS], value)
    }

    pub fn set_send_redirects(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[SEND_REDIRECTS], value)
    }

    pub fn set_shared_media(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[SHARED_MEDIA], value)
    }

    pub fn set_rp_filter(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[RP_FILTER], value)
    }

    pub fn set_accept_source_route(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_SOURCE_ROUTE], value)
    }

    pub fn set_bootp_relay(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[BOOTP_RELAY], value)
    }

    pub fn set_log_martians(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[LOG_MARTIANS], value)
    }

    pub fn set_tag(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[TAG], value)
    }

    pub fn set_arpfilter(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ARPFILTER], value)
    }

    pub fn set_medium_id(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[MEDIUM_ID], value)
    }

    pub fn set_noxfrm(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[NOXFRM], value)
    }

    pub fn set_nopolicy(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[NOPOLICY], value)
    }

    pub fn set_force_igmp_version(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[FORCE_IGMP_VERSION], value)
    }

    pub fn set_arp_announce(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ARP_ANNOUNCE], value)
    }

    pub fn set_arp_ignore(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ARP_IGNORE], value)
    }

    pub fn set_promote_secondaries(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[PROMOTE_SECONDARIES], value)
    }

    pub fn set_arp_accept(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ARP_ACCEPT], value)
    }

    pub fn set_arp_notify(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ARP_NOTIFY], value)
    }

    pub fn set_accept_local(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ACCEPT_LOCAL], value)
    }

    pub fn set_src_vmark(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[SRC_VMARK], value)
    }

    pub fn set_proxy_arp_pvlan(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[PROXY_ARP_PVLAN], value)
    }

    pub fn set_route_localnet(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[ROUTE_LOCALNET], value)
    }

    pub fn set_igmpv2_unsolicited_report_interval(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[IGMPV2_UNSOLICITED_REPORT_INTERVAL],
            value,
        )
    }

    pub fn set_igmpv3_unsolicited_report_interval(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[IGMPV3_UNSOLICITED_REPORT_INTERVAL],
            value,
        )
    }

    pub fn set_ignore_routes_with_linkdown(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[IGNORE_ROUTES_WITH_LINKDOWN],
            value,
        )
    }

    pub fn set_drop_unicast_in_l2_multicast(&mut self, value: i32) {
        NativeEndian::write_i32(
            &mut self.buffer.as_mut()[DROP_UNICAST_IN_L2_MULTICAST],
            value,
        )
    }

    pub fn set_drop_gratuitous_arp(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[DROP_GRATUITOUS_ARP], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkInetDevConf> for LinkInetDevConfBuffer<T> {
    fn parse(&self) -> Result<LinkInetDevConf, DecodeError> {
        Ok(LinkInetDevConf {
            forwarding: self.forwarding(),
            mc_forwarding: self.mc_forwarding(),
            proxy_arp: self.proxy_arp(),
            accept_redirects: self.accept_redirects(),
            secure_redirects: self.secure_redirects(),
            send_redirects: self.send_redirects(),
            shared_media: self.shared_media(),
            rp_filter: self.rp_filter(),
            accept_source_route: self.accept_source_route(),
            bootp_relay: self.bootp_relay(),
            log_martians: self.log_martians(),
            tag: self.tag(),
            arpfilter: self.arpfilter(),
            medium_id: self.medium_id(),
            noxfrm: self.noxfrm(),
            nopolicy: self.nopolicy(),
            force_igmp_version: self.force_igmp_version(),
            arp_announce: self.arp_announce(),
            arp_ignore: self.arp_ignore(),
            promote_secondaries: self.promote_secondaries(),
            arp_accept: self.arp_accept(),
            arp_notify: self.arp_notify(),
            accept_local: self.accept_local(),
            src_vmark: self.src_vmark(),
            proxy_arp_pvlan: self.proxy_arp_pvlan(),
            route_localnet: self.route_localnet(),
            igmpv2_unsolicited_report_interval: self.igmpv2_unsolicited_report_interval(),
            igmpv3_unsolicited_report_interval: self.igmpv3_unsolicited_report_interval(),
            ignore_routes_with_linkdown: self.ignore_routes_with_linkdown(),
            drop_unicast_in_l2_multicast: self.drop_unicast_in_l2_multicast(),
            drop_gratuitous_arp: self.drop_gratuitous_arp(),
        })
    }
}

impl Emitable for LinkInetDevConf {
    fn buffer_len(&self) -> usize {
        LINK_INET_DEV_CONF_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkInetDevConfBuffer::new(buffer);
        buffer.set_forwarding(self.forwarding);
        buffer.set_mc_forwarding(self.mc_forwarding);
        buffer.set_proxy_arp(self.proxy_arp);
        buffer.set_accept_redirects(self.accept_redirects);
        buffer.set_secure_redirects(self.secure_redirects);
        buffer.set_send_redirects(self.send_redirects);
        buffer.set_shared_media(self.shared_media);
        buffer.set_rp_filter(self.rp_filter);
        buffer.set_accept_source_route(self.accept_source_route);
        buffer.set_bootp_relay(self.bootp_relay);
        buffer.set_log_martians(self.log_martians);
        buffer.set_tag(self.tag);
        buffer.set_arpfilter(self.arpfilter);
        buffer.set_medium_id(self.medium_id);
        buffer.set_noxfrm(self.noxfrm);
        buffer.set_nopolicy(self.nopolicy);
        buffer.set_force_igmp_version(self.force_igmp_version);
        buffer.set_arp_announce(self.arp_announce);
        buffer.set_arp_ignore(self.arp_ignore);
        buffer.set_promote_secondaries(self.promote_secondaries);
        buffer.set_arp_accept(self.arp_accept);
        buffer.set_arp_notify(self.arp_notify);
        buffer.set_accept_local(self.accept_local);
        buffer.set_src_vmark(self.src_vmark);
        buffer.set_proxy_arp_pvlan(self.proxy_arp_pvlan);
        buffer.set_route_localnet(self.route_localnet);
        buffer.set_igmpv2_unsolicited_report_interval(self.igmpv2_unsolicited_report_interval);
        buffer.set_igmpv3_unsolicited_report_interval(self.igmpv3_unsolicited_report_interval);
        buffer.set_ignore_routes_with_linkdown(self.ignore_routes_with_linkdown);
        buffer.set_drop_unicast_in_l2_multicast(self.drop_unicast_in_l2_multicast);
        buffer.set_drop_gratuitous_arp(self.drop_gratuitous_arp);
    }
}
