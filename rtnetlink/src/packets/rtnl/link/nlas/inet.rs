use std::mem::size_of;

use constants::*;
use {DefaultNla, NativeNla, Nla, NlaBuffer, Parseable, Result};

#[repr(C)]
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

impl NativeNla for LinkInetDevConf {}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum LinkAfInetNla {
    DevConf(LinkInetDevConf),
    Unspec(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for LinkAfInetNla {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            DevConf(_) => size_of::<LinkInetDevConf>(),
            Other(ref nla) => nla.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            DevConf(ref dev_conf) => dev_conf.to_bytes(buffer),
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
    fn parse(&self) -> Result<LinkAfInetNla> {
        use self::LinkAfInetNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFLA_INET_UNSPEC => Unspec(payload.to_vec()),
            IFLA_INET_CONF => DevConf(LinkInetDevConf::from_bytes(payload)?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}
