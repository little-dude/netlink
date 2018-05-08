use constants;
use packet::{field, Error, Repr, Result};

use packet::link::Flags;

use byteorder::{ByteOrder, NativeEndian};

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum LinkLayerType {
    Netrom,
    Ether,
    Eether,
    Ax25,
    Pronet,
    Chaos,
    Ieee802,
    Arcnet,
    Appletlk,
    Dlci,
    Atm,
    Metricom,
    Ieee1394,
    Eui64,
    Infiniband,
    Slip,
    Cslip,
    Slip6,
    Cslip6,
    Rsrvd,
    Adapt,
    Rose,
    X25,
    Hwx25,
    Can,
    Ppp,
    Cisco,
    Hdlc,
    Lapb,
    Ddcmp,
    Rawhdlc,
    Rawip,
    Tunnel,
    Tunnel6,
    Frad,
    Skip,
    Loopback,
    Localtlk,
    Fddi,
    Bif,
    Sit,
    Ipddp,
    Ipgre,
    Pimreg,
    Hippi,
    Ash,
    Econet,
    Irda,
    Fcpp,
    Fcal,
    Fcpl,
    Fcfabric,
    Ieee802Tr,
    Ieee80211,
    Ieee80211Prism,
    Ieee80211Radiotap,
    Ieee802154,
    Ieee802154Monitor,
    Phonet,
    PhonetPipe,
    Caif,
    Ip6gre,
    Netlink,
    SixLowpan,
    Vsockmon,
    Void,
    None,
    Other(u32),
}

impl From<LinkLayerType> for u32 {
    fn from(llt: LinkLayerType) -> u32 {
        use self::LinkLayerType::*;
        let value = match llt {
            Netrom => constants::ARPHRD_NETROM,
            Ether => constants::ARPHRD_ETHER,
            Eether => constants::ARPHRD_EETHER,
            Ax25 => constants::ARPHRD_AX25,
            Pronet => constants::ARPHRD_PRONET,
            Chaos => constants::ARPHRD_CHAOS,
            Ieee802 => constants::ARPHRD_IEEE802,
            Arcnet => constants::ARPHRD_ARCNET,
            Appletlk => constants::ARPHRD_APPLETLK,
            Dlci => constants::ARPHRD_DLCI,
            Atm => constants::ARPHRD_ATM,
            Metricom => constants::ARPHRD_METRICOM,
            Ieee1394 => constants::ARPHRD_IEEE1394,
            Eui64 => constants::ARPHRD_EUI64,
            Infiniband => constants::ARPHRD_INFINIBAND,
            Slip => constants::ARPHRD_SLIP,
            Cslip => constants::ARPHRD_CSLIP,
            Slip6 => constants::ARPHRD_SLIP6,
            Cslip6 => constants::ARPHRD_CSLIP6,
            Rsrvd => constants::ARPHRD_RSRVD,
            Adapt => constants::ARPHRD_ADAPT,
            Rose => constants::ARPHRD_ROSE,
            X25 => constants::ARPHRD_X25,
            Hwx25 => constants::ARPHRD_HWX25,
            Can => constants::ARPHRD_CAN,
            Ppp => constants::ARPHRD_PPP,
            Cisco => constants::ARPHRD_CISCO,
            Hdlc => constants::ARPHRD_HDLC,
            Lapb => constants::ARPHRD_LAPB,
            Ddcmp => constants::ARPHRD_DDCMP,
            Rawhdlc => constants::ARPHRD_RAWHDLC,
            Rawip => constants::ARPHRD_RAWIP,
            Tunnel => constants::ARPHRD_TUNNEL,
            Tunnel6 => constants::ARPHRD_TUNNEL6,
            Frad => constants::ARPHRD_FRAD,
            Skip => constants::ARPHRD_SKIP,
            Loopback => constants::ARPHRD_LOOPBACK,
            Localtlk => constants::ARPHRD_LOCALTLK,
            Fddi => constants::ARPHRD_FDDI,
            Bif => constants::ARPHRD_BIF,
            Sit => constants::ARPHRD_SIT,
            Ipddp => constants::ARPHRD_IPDDP,
            Ipgre => constants::ARPHRD_IPGRE,
            Pimreg => constants::ARPHRD_PIMREG,
            Hippi => constants::ARPHRD_HIPPI,
            Ash => constants::ARPHRD_ASH,
            Econet => constants::ARPHRD_ECONET,
            Irda => constants::ARPHRD_IRDA,
            Fcpp => constants::ARPHRD_FCPP,
            Fcal => constants::ARPHRD_FCAL,
            Fcpl => constants::ARPHRD_FCPL,
            Fcfabric => constants::ARPHRD_FCFABRIC,
            Ieee802Tr => constants::ARPHRD_IEEE802_TR,
            Ieee80211 => constants::ARPHRD_IEEE80211,
            Ieee80211Prism => constants::ARPHRD_IEEE80211_PRISM,
            Ieee80211Radiotap => constants::ARPHRD_IEEE80211_RADIOTAP,
            Ieee802154 => constants::ARPHRD_IEEE802154,
            Ieee802154Monitor => constants::ARPHRD_IEEE802154_MONITOR,
            Phonet => constants::ARPHRD_PHONET,
            PhonetPipe => constants::ARPHRD_PHONET_PIPE,
            Caif => constants::ARPHRD_CAIF,
            Ip6gre => constants::ARPHRD_IP6GRE,
            Netlink => constants::ARPHRD_NETLINK,
            SixLowpan => constants::ARPHRD_6LOWPAN,
            Vsockmon => constants::ARPHRD_VSOCKMON,
            Void => constants::ARPHRD_VOID,
            None => constants::ARPHRD_NONE,
            Other(value) => return value,
        };
        value as u32
    }
}

impl From<u32> for LinkLayerType {
    fn from(v: u32) -> Self {
        match v as i32 {
            constants::ARPHRD_NETROM => LinkLayerType::Netrom,
            constants::ARPHRD_ETHER => LinkLayerType::Ether,
            constants::ARPHRD_EETHER => LinkLayerType::Eether,
            constants::ARPHRD_AX25 => LinkLayerType::Ax25,
            constants::ARPHRD_PRONET => LinkLayerType::Pronet,
            constants::ARPHRD_CHAOS => LinkLayerType::Chaos,
            constants::ARPHRD_IEEE802 => LinkLayerType::Ieee802,
            constants::ARPHRD_ARCNET => LinkLayerType::Arcnet,
            constants::ARPHRD_APPLETLK => LinkLayerType::Appletlk,
            constants::ARPHRD_DLCI => LinkLayerType::Dlci,
            constants::ARPHRD_ATM => LinkLayerType::Atm,
            constants::ARPHRD_METRICOM => LinkLayerType::Metricom,
            constants::ARPHRD_IEEE1394 => LinkLayerType::Ieee1394,
            constants::ARPHRD_EUI64 => LinkLayerType::Eui64,
            constants::ARPHRD_INFINIBAND => LinkLayerType::Infiniband,
            constants::ARPHRD_SLIP => LinkLayerType::Slip,
            constants::ARPHRD_CSLIP => LinkLayerType::Cslip,
            constants::ARPHRD_SLIP6 => LinkLayerType::Slip6,
            constants::ARPHRD_CSLIP6 => LinkLayerType::Cslip6,
            constants::ARPHRD_RSRVD => LinkLayerType::Rsrvd,
            constants::ARPHRD_ADAPT => LinkLayerType::Adapt,
            constants::ARPHRD_ROSE => LinkLayerType::Rose,
            constants::ARPHRD_X25 => LinkLayerType::X25,
            constants::ARPHRD_HWX25 => LinkLayerType::Hwx25,
            constants::ARPHRD_CAN => LinkLayerType::Can,
            constants::ARPHRD_PPP => LinkLayerType::Ppp,
            constants::ARPHRD_CISCO => LinkLayerType::Cisco,
            constants::ARPHRD_HDLC => LinkLayerType::Hdlc,
            constants::ARPHRD_LAPB => LinkLayerType::Lapb,
            constants::ARPHRD_DDCMP => LinkLayerType::Ddcmp,
            constants::ARPHRD_RAWHDLC => LinkLayerType::Rawhdlc,
            constants::ARPHRD_RAWIP => LinkLayerType::Rawip,
            constants::ARPHRD_TUNNEL => LinkLayerType::Tunnel,
            constants::ARPHRD_TUNNEL6 => LinkLayerType::Tunnel6,
            constants::ARPHRD_FRAD => LinkLayerType::Frad,
            constants::ARPHRD_SKIP => LinkLayerType::Skip,
            constants::ARPHRD_LOOPBACK => LinkLayerType::Loopback,
            constants::ARPHRD_LOCALTLK => LinkLayerType::Localtlk,
            constants::ARPHRD_FDDI => LinkLayerType::Fddi,
            constants::ARPHRD_BIF => LinkLayerType::Bif,
            constants::ARPHRD_SIT => LinkLayerType::Sit,
            constants::ARPHRD_IPDDP => LinkLayerType::Ipddp,
            constants::ARPHRD_IPGRE => LinkLayerType::Ipgre,
            constants::ARPHRD_PIMREG => LinkLayerType::Pimreg,
            constants::ARPHRD_HIPPI => LinkLayerType::Hippi,
            constants::ARPHRD_ASH => LinkLayerType::Ash,
            constants::ARPHRD_ECONET => LinkLayerType::Econet,
            constants::ARPHRD_IRDA => LinkLayerType::Irda,
            constants::ARPHRD_FCPP => LinkLayerType::Fcpp,
            constants::ARPHRD_FCAL => LinkLayerType::Fcal,
            constants::ARPHRD_FCPL => LinkLayerType::Fcpl,
            constants::ARPHRD_FCFABRIC => LinkLayerType::Fcfabric,
            constants::ARPHRD_IEEE802_TR => LinkLayerType::Ieee802Tr,
            constants::ARPHRD_IEEE80211 => LinkLayerType::Ieee80211,
            constants::ARPHRD_IEEE80211_PRISM => LinkLayerType::Ieee80211Prism,
            constants::ARPHRD_IEEE80211_RADIOTAP => LinkLayerType::Ieee80211Radiotap,
            constants::ARPHRD_IEEE802154 => LinkLayerType::Ieee802154,
            constants::ARPHRD_IEEE802154_MONITOR => LinkLayerType::Ieee802154Monitor,
            constants::ARPHRD_PHONET => LinkLayerType::Phonet,
            constants::ARPHRD_PHONET_PIPE => LinkLayerType::PhonetPipe,
            constants::ARPHRD_CAIF => LinkLayerType::Caif,
            constants::ARPHRD_IP6GRE => LinkLayerType::Ip6gre,
            constants::ARPHRD_NETLINK => LinkLayerType::Netlink,
            constants::ARPHRD_6LOWPAN => LinkLayerType::SixLowpan,
            constants::ARPHRD_VSOCKMON => LinkLayerType::Vsockmon,
            constants::ARPHRD_VOID => LinkLayerType::Void,
            constants::ARPHRD_NONE => LinkLayerType::None,
            other => LinkLayerType::Other(other as u32),
        }
    }
}

const ADDRESS_FAMILY: field::Index = 0;
const UNUSED: field::Index = 1;
const LINK_LAYER_TYPE: field::Field = 2..4;
const LINK_INDEX: field::Field = 4..8;
const FLAGS: field::Field = 8..12;
const FLAGS_CHANGE_MASK: field::Field = 12..16;
const ATTRIBUTES: field::Rest = 16..;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the address family field
    pub fn address_family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[ADDRESS_FAMILY]
    }

    /// Return the link layer type field
    pub fn link_layer_type(&self) -> LinkLayerType {
        let data = self.buffer.as_ref();
        LinkLayerType::from(NativeEndian::read_u32(&data[LINK_LAYER_TYPE]))
    }

    /// Return the link index field
    pub fn link_index(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[LINK_INDEX])
    }

    /// Return the flags field
    pub fn flags(&self) -> Flags {
        let data = self.buffer.as_ref();
        Flags::from(NativeEndian::read_u32(&data[FLAGS]))
    }
}
