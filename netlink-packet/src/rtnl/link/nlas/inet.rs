use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use constants::*;
use {DecodeError, DefaultNla, Nla, NlaBuffer, Parseable};

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

const LINK_INET_DEV_CONF_LEN: usize = 31 * 4;

impl LinkInetDevConf {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < LINK_INET_DEV_CONF_LEN {
            return Err(DecodeError::from(format!(
                "LinkInetDevConf is {} bytes, buffer is only {} bytes: {:#x?}",
                LINK_INET_DEV_CONF_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(LinkInetDevConf {
            forwarding: NativeEndian::read_i32(&buf[0..4]),
            mc_forwarding: NativeEndian::read_i32(&buf[4..8]),
            proxy_arp: NativeEndian::read_i32(&buf[8..12]),
            accept_redirects: NativeEndian::read_i32(&buf[12..16]),
            secure_redirects: NativeEndian::read_i32(&buf[16..20]),
            send_redirects: NativeEndian::read_i32(&buf[20..24]),
            shared_media: NativeEndian::read_i32(&buf[24..28]),
            rp_filter: NativeEndian::read_i32(&buf[28..32]),
            accept_source_route: NativeEndian::read_i32(&buf[32..36]),
            bootp_relay: NativeEndian::read_i32(&buf[36..40]),
            log_martians: NativeEndian::read_i32(&buf[40..44]),
            tag: NativeEndian::read_i32(&buf[44..48]),
            arpfilter: NativeEndian::read_i32(&buf[48..52]),
            medium_id: NativeEndian::read_i32(&buf[52..56]),
            noxfrm: NativeEndian::read_i32(&buf[56..60]),
            nopolicy: NativeEndian::read_i32(&buf[60..64]),
            force_igmp_version: NativeEndian::read_i32(&buf[64..68]),
            arp_announce: NativeEndian::read_i32(&buf[68..72]),
            arp_ignore: NativeEndian::read_i32(&buf[72..76]),
            promote_secondaries: NativeEndian::read_i32(&buf[76..80]),
            arp_accept: NativeEndian::read_i32(&buf[80..84]),
            arp_notify: NativeEndian::read_i32(&buf[84..88]),
            accept_local: NativeEndian::read_i32(&buf[88..92]),
            src_vmark: NativeEndian::read_i32(&buf[92..96]),
            proxy_arp_pvlan: NativeEndian::read_i32(&buf[96..100]),
            route_localnet: NativeEndian::read_i32(&buf[100..104]),
            igmpv2_unsolicited_report_interval: NativeEndian::read_i32(&buf[104..108]),
            igmpv3_unsolicited_report_interval: NativeEndian::read_i32(&buf[108..112]),
            ignore_routes_with_linkdown: NativeEndian::read_i32(&buf[112..116]),
            drop_unicast_in_l2_multicast: NativeEndian::read_i32(&buf[116..120]),
            drop_gratuitous_arp: NativeEndian::read_i32(&buf[120..124]),
        })
    }
    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < LINK_INET_DEV_CONF_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but LinkInetDevConf is {} bytes",
                buf.len(),
                LINK_INET_DEV_CONF_LEN
            )));
        }
        NativeEndian::write_i32(&mut buf[0..4], self.forwarding);
        NativeEndian::write_i32(&mut buf[4..8], self.mc_forwarding);
        NativeEndian::write_i32(&mut buf[8..12], self.proxy_arp);
        NativeEndian::write_i32(&mut buf[12..16], self.accept_redirects);
        NativeEndian::write_i32(&mut buf[16..20], self.secure_redirects);
        NativeEndian::write_i32(&mut buf[20..24], self.send_redirects);
        NativeEndian::write_i32(&mut buf[24..28], self.shared_media);
        NativeEndian::write_i32(&mut buf[28..32], self.rp_filter);
        NativeEndian::write_i32(&mut buf[32..36], self.accept_source_route);
        NativeEndian::write_i32(&mut buf[36..40], self.bootp_relay);
        NativeEndian::write_i32(&mut buf[40..44], self.log_martians);
        NativeEndian::write_i32(&mut buf[44..48], self.tag);
        NativeEndian::write_i32(&mut buf[48..52], self.arpfilter);
        NativeEndian::write_i32(&mut buf[52..56], self.medium_id);
        NativeEndian::write_i32(&mut buf[56..60], self.noxfrm);
        NativeEndian::write_i32(&mut buf[60..64], self.nopolicy);
        NativeEndian::write_i32(&mut buf[64..68], self.force_igmp_version);
        NativeEndian::write_i32(&mut buf[68..72], self.arp_announce);
        NativeEndian::write_i32(&mut buf[72..76], self.arp_ignore);
        NativeEndian::write_i32(&mut buf[76..80], self.promote_secondaries);
        NativeEndian::write_i32(&mut buf[80..84], self.arp_accept);
        NativeEndian::write_i32(&mut buf[84..88], self.arp_notify);
        NativeEndian::write_i32(&mut buf[88..92], self.accept_local);
        NativeEndian::write_i32(&mut buf[92..96], self.src_vmark);
        NativeEndian::write_i32(&mut buf[96..100], self.proxy_arp_pvlan);
        NativeEndian::write_i32(&mut buf[100..104], self.route_localnet);
        NativeEndian::write_i32(&mut buf[104..108], self.igmpv2_unsolicited_report_interval);
        NativeEndian::write_i32(&mut buf[108..112], self.igmpv3_unsolicited_report_interval);
        NativeEndian::write_i32(&mut buf[112..116], self.ignore_routes_with_linkdown);
        NativeEndian::write_i32(&mut buf[116..120], self.drop_unicast_in_l2_multicast);
        NativeEndian::write_i32(&mut buf[120..124], self.drop_gratuitous_arp);
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum LinkAfInetNla {
    DevConf(LinkInetDevConf),
    Unspec(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for LinkAfInetNla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            DevConf(_) => size_of::<LinkInetDevConf>(),
            Other(ref nla) => nla.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            DevConf(ref dev_conf) => dev_conf.to_bytes(buffer).expect("check the buffer length before calling emit_value()!"),
            Other(ref nla)  => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(_) => IFLA_INET_UNSPEC,
            DevConf(_) => IFLA_INET_CONF,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkAfInetNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<LinkAfInetNla, DecodeError> {
        use self::LinkAfInetNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFLA_INET_UNSPEC => Unspec(payload.to_vec()),
            IFLA_INET_CONF => DevConf(
                LinkInetDevConf::from_bytes(payload).context("invalid IFLA_INET_CONF value")?,
            ),
            kind => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context(format!("unknown NLA type {}", kind))?,
            ),
        })
    }
}
