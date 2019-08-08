pub const ARPHRD_NETROM: u16 = 0;
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_EETHER: u16 = 2;
pub const ARPHRD_AX25: u16 = 3;
pub const ARPHRD_PRONET: u16 = 4;
pub const ARPHRD_CHAOS: u16 = 5;
pub const ARPHRD_IEEE802: u16 = 6;
pub const ARPHRD_ARCNET: u16 = 7;
pub const ARPHRD_APPLETLK: u16 = 8;
pub const ARPHRD_DLCI: u16 = 15;
pub const ARPHRD_ATM: u16 = 19;
pub const ARPHRD_METRICOM: u16 = 23;
pub const ARPHRD_IEEE1394: u16 = 24;
pub const ARPHRD_EUI64: u16 = 27;
pub const ARPHRD_INFINIBAND: u16 = 32;
pub const ARPHRD_SLIP: u16 = 256;
pub const ARPHRD_CSLIP: u16 = 257;
pub const ARPHRD_SLIP6: u16 = 258;
pub const ARPHRD_CSLIP6: u16 = 259;
pub const ARPHRD_RSRVD: u16 = 260;
pub const ARPHRD_ADAPT: u16 = 264;
pub const ARPHRD_ROSE: u16 = 270;
pub const ARPHRD_X25: u16 = 271;
pub const ARPHRD_HWX25: u16 = 272;
pub const ARPHRD_CAN: u16 = 280;
pub const ARPHRD_PPP: u16 = 512;
pub const ARPHRD_CISCO: u16 = 513;
pub const ARPHRD_HDLC: u16 = 513;
pub const ARPHRD_LAPB: u16 = 516;
pub const ARPHRD_DDCMP: u16 = 517;
pub const ARPHRD_RAWHDLC: u16 = 518;
pub const ARPHRD_RAWIP: u16 = 519;
pub const ARPHRD_TUNNEL: u16 = 768;
pub const ARPHRD_TUNNEL6: u16 = 769;
pub const ARPHRD_FRAD: u16 = 770;
pub const ARPHRD_SKIP: u16 = 771;
pub const ARPHRD_LOOPBACK: u16 = 772;
pub const ARPHRD_LOCALTLK: u16 = 773;
pub const ARPHRD_FDDI: u16 = 774;
pub const ARPHRD_BIF: u16 = 775;
pub const ARPHRD_SIT: u16 = 776;
pub const ARPHRD_IPDDP: u16 = 777;
pub const ARPHRD_IPGRE: u16 = 778;
pub const ARPHRD_PIMREG: u16 = 779;
pub const ARPHRD_HIPPI: u16 = 780;
pub const ARPHRD_ASH: u16 = 781;
pub const ARPHRD_ECONET: u16 = 782;
pub const ARPHRD_IRDA: u16 = 783;
pub const ARPHRD_FCPP: u16 = 784;
pub const ARPHRD_FCAL: u16 = 785;
pub const ARPHRD_FCPL: u16 = 786;
pub const ARPHRD_FCFABRIC: u16 = 787;
pub const ARPHRD_IEEE802_TR: u16 = 800;
pub const ARPHRD_IEEE80211: u16 = 801;
pub const ARPHRD_IEEE80211_PRISM: u16 = 802;
pub const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
pub const ARPHRD_IEEE802154: u16 = 804;
pub const ARPHRD_IEEE802154_MONITOR: u16 = 805;
pub const ARPHRD_PHONET: u16 = 820;
pub const ARPHRD_PHONET_PIPE: u16 = 821;
pub const ARPHRD_CAIF: u16 = 822;
pub const ARPHRD_IP6GRE: u16 = 823;
pub const ARPHRD_NETLINK: u16 = 824;
pub const ARPHRD_6LOWPAN: u16 = 825;
pub const ARPHRD_VSOCKMON: u16 = 826;
pub const ARPHRD_VOID: u16 = 65535;
pub const ARPHRD_NONE: u16 = 65534;

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum LinkLayerType {
    /// Link type is `ARPHRD_NETROM`
    Netrom,
    /// Link type is `ARPHRD_ETHER`
    Ether,
    /// Link type is `ARPHRD_EETHER`
    Eether,
    /// Link type is `ARPHRD_AX25`
    Ax25,
    /// Link type is `ARPHRD_PRONET`
    Pronet,
    /// Link type is `ARPHRD_CHAOS`
    Chaos,
    /// Link type is `ARPHRD_IEEE802`
    Ieee802,
    /// Link type is `ARPHRD_ARCNET`
    Arcnet,
    /// Link type is `ARPHRD_APPLETLK`
    Appletlk,
    /// Link type is `ARPHRD_DLCI`
    Dlci,
    /// Link type is `ARPHRD_ATM`
    Atm,
    /// Link type is `ARPHRD_METRICOM`
    Metricom,
    /// Link type is `ARPHRD_IEEE1394`
    Ieee1394,
    /// Link type is `ARPHRD_EUI64`
    Eui64,
    /// Link type is `ARPHRD_INFINIBAND`
    Infiniband,
    /// Link type is `ARPHRD_SLIP`
    Slip,
    /// Link type is `ARPHRD_CSLIP`
    Cslip,
    /// Link type is `ARPHRD_SLIP6`
    Slip6,
    /// Link type is `ARPHRD_CSLIP6`
    Cslip6,
    /// Link type is `ARPHRD_RSRVD`
    Rsrvd,
    /// Link type is `ARPHRD_ADAPT`
    Adapt,
    /// Link type is `ARPHRD_ROSE`
    Rose,
    /// Link type is `ARPHRD_X25`
    X25,
    /// Link type is `ARPHRD_HWX25`
    Hwx25,
    /// Link type is `ARPHRD_CAN`
    Can,
    /// Link type is `ARPHRD_PPP`
    Ppp,
    /// Link type is `ARPHRD_CISCO` or `ARPHRD_HDLC`
    Hdlc,
    /// Link type is `ARPHRD_LAPB`
    Lapb,
    /// Link type is `ARPHRD_DDCMP`
    Ddcmp,
    /// Link type is `ARPHRD_RAWHDLC`
    Rawhdlc,
    /// Link type is `ARPHRD_RAWIP`
    Rawip,
    /// Link type is `ARPHRD_TUNNEL`
    Tunnel,
    /// Link type is `ARPHRD_TUNNEL6`
    Tunnel6,
    /// Link type is `ARPHRD_FRAD`
    Frad,
    /// Link type is `ARPHRD_SKIP`
    Skip,
    /// Link type is `ARPHRD_LOOPBACK`
    Loopback,
    /// Link type is `ARPHRD_LOCALTLK`
    Localtlk,
    /// Link type is `ARPHRD_FDDI`
    Fddi,
    /// Link type is `ARPHRD_BIF`
    Bif,
    /// Link type is `ARPHRD_SIT`
    Sit,
    /// Link type is `ARPHRD_IPDDP`
    Ipddp,
    /// Link type is `ARPHRD_IPGRE`
    IpGre,
    /// Link type is `ARPHRD_PIMREG`
    Pimreg,
    /// Link type is `ARPHRD_HIPPI`
    Hippi,
    /// Link type is `ARPHRD_ASH`
    Ash,
    /// Link type is `ARPHRD_ECONET`
    Econet,
    /// Link type is `ARPHRD_IRDA`
    Irda,
    /// Link type is `ARPHRD_FCPP`
    Fcpp,
    /// Link type is `ARPHRD_FCAL`
    Fcal,
    /// Link type is `ARPHRD_FCPL`
    Fcpl,
    /// Link type is `ARPHRD_FCFABRIC`
    Fcfabric,
    /// Link type is `ARPHRD_IEEE802_TR`
    Ieee802Tr,
    /// Link type is `ARPHRD_IEEE80211`
    Ieee80211,
    /// Link type is `ARPHRD_IEEE80211_PRISM`
    Ieee80211Prism,
    /// Link type is `ARPHRD_IEEE80211_RADIOTAP`
    Ieee80211Radiotap,
    /// Link type is `ARPHRD_IEEE802154`
    Ieee802154,
    /// Link type is `ARPHRD_IEEE802154_MONITOR`
    Ieee802154Monitor,
    /// Link type is `ARPHRD_PHONET`
    Phonet,
    /// Link type is `ARPHRD_PHONET_PIPE`
    PhonetPipe,
    /// Link type is `ARPHRD_CAIF`
    Caif,
    /// Link type is `ARPHRD_IP6GRE`
    Ip6Gre,
    /// Link type is `ARPHRD_NETLINK`
    Netlink,
    /// Link type is `ARPHRD_6LOWPAN`
    SixLowpan,
    /// Link type is `ARPHRD_VSOCKMON`
    Vsockmon,
    /// Link type is `ARPHRD_VOID`
    Void,
    /// Link type is `ARPHRD_NONE`
    None,
    /// Link type is unknown
    Other(u16),
}

impl From<LinkLayerType> for u16 {
    fn from(llt: LinkLayerType) -> u16 {
        use self::LinkLayerType::*;
        match llt {
            Netrom => ARPHRD_NETROM,
            Ether => ARPHRD_ETHER,
            Eether => ARPHRD_EETHER,
            Ax25 => ARPHRD_AX25,
            Pronet => ARPHRD_PRONET,
            Chaos => ARPHRD_CHAOS,
            Ieee802 => ARPHRD_IEEE802,
            Arcnet => ARPHRD_ARCNET,
            Appletlk => ARPHRD_APPLETLK,
            Dlci => ARPHRD_DLCI,
            Atm => ARPHRD_ATM,
            Metricom => ARPHRD_METRICOM,
            Ieee1394 => ARPHRD_IEEE1394,
            Eui64 => ARPHRD_EUI64,
            Infiniband => ARPHRD_INFINIBAND,
            Slip => ARPHRD_SLIP,
            Cslip => ARPHRD_CSLIP,
            Slip6 => ARPHRD_SLIP6,
            Cslip6 => ARPHRD_CSLIP6,
            Rsrvd => ARPHRD_RSRVD,
            Adapt => ARPHRD_ADAPT,
            Rose => ARPHRD_ROSE,
            X25 => ARPHRD_X25,
            Hwx25 => ARPHRD_HWX25,
            Can => ARPHRD_CAN,
            Ppp => ARPHRD_PPP,
            Hdlc => ARPHRD_HDLC,
            Lapb => ARPHRD_LAPB,
            Ddcmp => ARPHRD_DDCMP,
            Rawhdlc => ARPHRD_RAWHDLC,
            Rawip => ARPHRD_RAWIP,
            Tunnel => ARPHRD_TUNNEL,
            Tunnel6 => ARPHRD_TUNNEL6,
            Frad => ARPHRD_FRAD,
            Skip => ARPHRD_SKIP,
            Loopback => ARPHRD_LOOPBACK,
            Localtlk => ARPHRD_LOCALTLK,
            Fddi => ARPHRD_FDDI,
            Bif => ARPHRD_BIF,
            Sit => ARPHRD_SIT,
            Ipddp => ARPHRD_IPDDP,
            IpGre => ARPHRD_IPGRE,
            Pimreg => ARPHRD_PIMREG,
            Hippi => ARPHRD_HIPPI,
            Ash => ARPHRD_ASH,
            Econet => ARPHRD_ECONET,
            Irda => ARPHRD_IRDA,
            Fcpp => ARPHRD_FCPP,
            Fcal => ARPHRD_FCAL,
            Fcpl => ARPHRD_FCPL,
            Fcfabric => ARPHRD_FCFABRIC,
            Ieee802Tr => ARPHRD_IEEE802_TR,
            Ieee80211 => ARPHRD_IEEE80211,
            Ieee80211Prism => ARPHRD_IEEE80211_PRISM,
            Ieee80211Radiotap => ARPHRD_IEEE80211_RADIOTAP,
            Ieee802154 => ARPHRD_IEEE802154,
            Ieee802154Monitor => ARPHRD_IEEE802154_MONITOR,
            Phonet => ARPHRD_PHONET,
            PhonetPipe => ARPHRD_PHONET_PIPE,
            Caif => ARPHRD_CAIF,
            Ip6Gre => ARPHRD_IP6GRE,
            Netlink => ARPHRD_NETLINK,
            SixLowpan => ARPHRD_6LOWPAN,
            Vsockmon => ARPHRD_VSOCKMON,
            Void => ARPHRD_VOID,
            None => ARPHRD_NONE,
            Other(value) => value,
        }
    }
}

impl From<u16> for LinkLayerType {
    fn from(v: u16) -> Self {
        match v {
            ARPHRD_NETROM => LinkLayerType::Netrom,
            ARPHRD_ETHER => LinkLayerType::Ether,
            ARPHRD_EETHER => LinkLayerType::Eether,
            ARPHRD_AX25 => LinkLayerType::Ax25,
            ARPHRD_PRONET => LinkLayerType::Pronet,
            ARPHRD_CHAOS => LinkLayerType::Chaos,
            ARPHRD_IEEE802 => LinkLayerType::Ieee802,
            ARPHRD_ARCNET => LinkLayerType::Arcnet,
            ARPHRD_APPLETLK => LinkLayerType::Appletlk,
            ARPHRD_DLCI => LinkLayerType::Dlci,
            ARPHRD_ATM => LinkLayerType::Atm,
            ARPHRD_METRICOM => LinkLayerType::Metricom,
            ARPHRD_IEEE1394 => LinkLayerType::Ieee1394,
            ARPHRD_EUI64 => LinkLayerType::Eui64,
            ARPHRD_INFINIBAND => LinkLayerType::Infiniband,
            ARPHRD_SLIP => LinkLayerType::Slip,
            ARPHRD_CSLIP => LinkLayerType::Cslip,
            ARPHRD_SLIP6 => LinkLayerType::Slip6,
            ARPHRD_CSLIP6 => LinkLayerType::Cslip6,
            ARPHRD_RSRVD => LinkLayerType::Rsrvd,
            ARPHRD_ADAPT => LinkLayerType::Adapt,
            ARPHRD_ROSE => LinkLayerType::Rose,
            ARPHRD_X25 => LinkLayerType::X25,
            ARPHRD_HWX25 => LinkLayerType::Hwx25,
            ARPHRD_CAN => LinkLayerType::Can,
            ARPHRD_PPP => LinkLayerType::Ppp,
            ARPHRD_HDLC => LinkLayerType::Hdlc,
            ARPHRD_LAPB => LinkLayerType::Lapb,
            ARPHRD_DDCMP => LinkLayerType::Ddcmp,
            ARPHRD_RAWHDLC => LinkLayerType::Rawhdlc,
            ARPHRD_RAWIP => LinkLayerType::Rawip,
            ARPHRD_TUNNEL => LinkLayerType::Tunnel,
            ARPHRD_TUNNEL6 => LinkLayerType::Tunnel6,
            ARPHRD_FRAD => LinkLayerType::Frad,
            ARPHRD_SKIP => LinkLayerType::Skip,
            ARPHRD_LOOPBACK => LinkLayerType::Loopback,
            ARPHRD_LOCALTLK => LinkLayerType::Localtlk,
            ARPHRD_FDDI => LinkLayerType::Fddi,
            ARPHRD_BIF => LinkLayerType::Bif,
            ARPHRD_SIT => LinkLayerType::Sit,
            ARPHRD_IPDDP => LinkLayerType::Ipddp,
            ARPHRD_IPGRE => LinkLayerType::IpGre,
            ARPHRD_PIMREG => LinkLayerType::Pimreg,
            ARPHRD_HIPPI => LinkLayerType::Hippi,
            ARPHRD_ASH => LinkLayerType::Ash,
            ARPHRD_ECONET => LinkLayerType::Econet,
            ARPHRD_IRDA => LinkLayerType::Irda,
            ARPHRD_FCPP => LinkLayerType::Fcpp,
            ARPHRD_FCAL => LinkLayerType::Fcal,
            ARPHRD_FCPL => LinkLayerType::Fcpl,
            ARPHRD_FCFABRIC => LinkLayerType::Fcfabric,
            ARPHRD_IEEE802_TR => LinkLayerType::Ieee802Tr,
            ARPHRD_IEEE80211 => LinkLayerType::Ieee80211,
            ARPHRD_IEEE80211_PRISM => LinkLayerType::Ieee80211Prism,
            ARPHRD_IEEE80211_RADIOTAP => LinkLayerType::Ieee80211Radiotap,
            ARPHRD_IEEE802154 => LinkLayerType::Ieee802154,
            ARPHRD_IEEE802154_MONITOR => LinkLayerType::Ieee802154Monitor,
            ARPHRD_PHONET => LinkLayerType::Phonet,
            ARPHRD_PHONET_PIPE => LinkLayerType::PhonetPipe,
            ARPHRD_CAIF => LinkLayerType::Caif,
            ARPHRD_IP6GRE => LinkLayerType::Ip6Gre,
            ARPHRD_NETLINK => LinkLayerType::Netlink,
            ARPHRD_6LOWPAN => LinkLayerType::SixLowpan,
            ARPHRD_VSOCKMON => LinkLayerType::Vsockmon,
            ARPHRD_VOID => LinkLayerType::Void,
            ARPHRD_NONE => LinkLayerType::None,
            other => LinkLayerType::Other(other),
        }
    }
}

impl Default for LinkLayerType {
    fn default() -> Self {
        LinkLayerType::Ether
    }
}
