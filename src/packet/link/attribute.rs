use byteorder::{ByteOrder, NativeEndian};
use constants;
use packet::attribute::{Attribute, DefaultAttribute, Packet};
use packet::{Error, Result};

pub const IFLA_UNSPEC: u16 = constants::IFLA_UNSPEC as u16;
pub const IFLA_ADDRESS: u16 = constants::IFLA_ADDRESS as u16;
pub const IFLA_BROADCAST: u16 = constants::IFLA_BROADCAST as u16;
pub const IFLA_IFNAME: u16 = constants::IFLA_IFNAME as u16;
pub const IFLA_MTU: u16 = constants::IFLA_MTU as u16;
pub const IFLA_LINK: u16 = constants::IFLA_LINK as u16;
pub const IFLA_QDISC: u16 = constants::IFLA_QDISC as u16;
pub const IFLA_STATS: u16 = constants::IFLA_STATS as u16;
// pub const IFLA_COST: u16 = constants::IFLA_COST as u16;
// pub const IFLA_PRIORITY: u16 = constants::IFLA_PRIORITY as u16;
// pub const IFLA_MASTER: u16 = constants::IFLA_MASTER as u16;
// pub const IFLA_WIRELESS: u16 = constants::IFLA_WIRELESS as u16;
// pub const IFLA_PROTINFO: u16 = constants::IFLA_PROTINFO as u16;
pub const IFLA_TXQLEN: u16 = constants::IFLA_TXQLEN as u16;
// pub const IFLA_MAP: u16 = constants::IFLA_MAP as u16;
// pub const IFLA_WEIGHT: u16 = constants::IFLA_WEIGHT as u16;
pub const IFLA_OPERSTATE: u16 = constants::IFLA_OPERSTATE as u16;
pub const IFLA_LINKMODE: u16 = constants::IFLA_LINKMODE as u16;
// pub const IFLA_LINKINFO: u16 = constants::IFLA_LINKINFO as u16;
// pub const IFLA_NET_NS_PID: u16 = constants::IFLA_NET_NS_PID as u16;
// pub const IFLA_IFALIAS: u16 = constants::IFLA_IFALIAS as u16;
// pub const IFLA_NUM_VF: u16 = constants::IFLA_NUM_VF as u16;
// pub const IFLA_VFINFO_LIST: u16 = constants::IFLA_VFINFO_LIST as u16;
// pub const IFLA_STATS64: u16 = constants::IFLA_STATS64 as u16;
// pub const IFLA_VF_PORTS: u16 = constants::IFLA_VF_PORTS as u16;
// pub const IFLA_PORT_SELF: u16 = constants::IFLA_PORT_SELF as u16;
// pub const IFLA_AF_SPEC: u16 = constants::IFLA_AF_SPEC as u16;
pub const IFLA_GROUP: u16 = constants::IFLA_GROUP as u16;
// pub const IFLA_NET_NS_FD: u16 = constants::IFLA_NET_NS_FD as u16;
// pub const IFLA_EXT_MASK: u16 = constants::IFLA_EXT_MASK as u16;
pub const IFLA_PROMISCUITY: u16 = constants::IFLA_PROMISCUITY as u16;
pub const IFLA_NUM_TX_QUEUES: u16 = constants::IFLA_NUM_TX_QUEUES as u16;
// pub const IFLA_NUM_RX_QUEUES: u16 = constants::IFLA_NUM_RX_QUEUES as u16;
// pub const IFLA_CARRIER: u16 = constants::IFLA_CARRIER as u16;
// pub const IFLA_PHYS_PORT_ID: u16 = constants::IFLA_PHYS_PORT_ID as u16;
// pub const IFLA_CARRIER_CHANGES: u16 = constants::IFLA_CARRIER_CHANGES as u16;
// pub const IFLA_PHYS_SWITCH_ID: u16 = constants::IFLA_PHYS_SWITCH_ID as u16;
// pub const IFLA_LINK_NETNSID: u16 = constants::IFLA_LINK_NETNSID as u16;
// pub const IFLA_PHYS_PORT_NAME: u16 = constants::IFLA_PHYS_PORT_NAME as u16;
// pub const IFLA_PROTO_DOWN: u16 = constants::IFLA_PROTO_DOWN as u16;
// pub const IFLA_GSO_MAX_SEGS: u16 = constants::IFLA_GSO_MAX_SEGS as u16;
// pub const IFLA_GSO_MAX_SIZE: u16 = constants::IFLA_GSO_MAX_SIZE as u16;
// pub const IFLA_PAD: u16 = constants::IFLA_PAD as u16;
// pub const IFLA_XDP: u16 = constants::IFLA_XDP as u16;
// pub const IFLA_EVENT: u16 = constants::IFLA_EVENT as u16;
// pub const IFLA_NEW_NETNSID: u16 = constants::IFLA_NEW_NETNSID as u16;
// pub const IFLA_IF_NETNSID: u16 = constants::IFLA_IF_NETNSID as u16;
// pub const IFLA_CARRIER_UP_COUNT: u16 = constants::IFLA_CARRIER_UP_COUNT as u16;
// pub const IFLA_CARRIER_DOWN_COUNT: u16 = constants::IFLA_CARRIER_DOWN_COUNT as u16;
// pub const IFLA_NEW_IFINDEX: u16 = constants::IFLA_NEW_IFINDEX as u16;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkAttribute {
    Unspec(Vec<u8>),
    Address([u8; 6]),
    Broadcast([u8; 6]),
    Ifname(String),
    OperState(u8),
    LinkMode(u8),
    Mtu(u32),
    NumTxQueues(u32),
    Promiscuity(u32),
    Group(u32),
    TxQueueLen(u32),
    Link(Vec<u8>),
    Qdisc(Vec<u8>),
    Stats(Vec<u8>),
    Other(DefaultAttribute),
    Malformed(DefaultAttribute),
}

impl Attribute for LinkAttribute {
    #[allow(unused_attributes)]
    #[rustfmt_skip]
    fn length(&self) -> usize {
        use self::LinkAttribute::*;
        match *self {
            // Vec<u8>
            Unspec(ref v)
                | Link(ref v)
                | Qdisc(ref v)
                | Stats(ref v) => v.len(),

            // strings: +1 because we need to append a nul byte
            Ifname(ref name) => name.as_bytes().len() + 1,

            // Mac addresses are arrays of 6 bytes
            Address(_) | Broadcast(_) => 6,

            // u8
            OperState(_) | LinkMode(_) => 1,

            // u32
            Mtu(_)
                | NumTxQueues(_)
                | Promiscuity(_)
                | Group(_)
                | TxQueueLen(_) => 4,

            // Defaults
            Other(ref attr) | Malformed(ref attr) => attr.length(),
        }
    }

    #[allow(unused_attributes)]
    #[rustfmt_skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkAttribute::*;
        match *self {
            // Vec<u8>
            Unspec(ref v)
                | Link(ref v)
                | Qdisc(ref v)
                | Stats(ref v) => buffer.copy_from_slice(v.as_slice()),

            // String
            Ifname(ref name) => {
                buffer.copy_from_slice(name.as_bytes());
                buffer[name.as_bytes().len()] = 0;
            }

            // u8
            OperState(ref val) | LinkMode(ref val) => buffer[0] = *val,

            // mac address
            Address(ref eui) | Broadcast(ref eui) => buffer.copy_from_slice(&eui[..]),

            // u32
            Mtu(ref v)
                | NumTxQueues(ref v)
                | Promiscuity(ref v)
                | TxQueueLen(ref v)
                | Group(ref v) => NativeEndian::write_u32(buffer, *v),

            // default attributes
            Other(ref attr) | Malformed(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkAttribute::*;
        match *self {
            // Vec<u8>
            Unspec(_) => IFLA_UNSPEC,
            Link(_) => IFLA_LINK,
            Qdisc(_) => IFLA_QDISC,
            Stats(_) => IFLA_STATS,
            // Mac address
            Address(_) => IFLA_ADDRESS,
            Broadcast(_) => IFLA_BROADCAST,
            // String
            Ifname(_) => IFLA_IFNAME,
            // u8
            OperState(_) => IFLA_OPERSTATE,
            LinkMode(_) => IFLA_LINKMODE,
            // u32
            Mtu(_) => IFLA_MTU,
            NumTxQueues(_) => IFLA_NUM_TX_QUEUES,
            Promiscuity(_) => IFLA_PROMISCUITY,
            Group(_) => IFLA_GROUP,
            TxQueueLen(_) => IFLA_TXQLEN,
            // Default attributes
            Other(ref attr) | Malformed(ref attr) => attr.kind(),
        }
    }

    /// # Panic
    ///
    /// This panics on packets for which the "length" field value is is wrong. The
    /// `Packet` argument must be checked before being passed to this method.
    fn from_packet<'a, T: AsRef<[u8]> + ?Sized>(packet: Packet<&'a T>) -> Result<Self> {
        LinkAttribute::parse_value(packet).or_else(|_| {
            Ok(LinkAttribute::Malformed(DefaultAttribute::from_packet(
                packet,
            )?))
        })
    }
}

impl LinkAttribute {
    fn parse_value<'a, T: AsRef<[u8]> + ?Sized>(packet: Packet<&'a T>) -> Result<Self> {
        use self::LinkAttribute::*;
        let payload = packet.value();
        Ok(match packet.kind() {
            // Vec<u8>
            IFLA_UNSPEC => Unspec(payload.to_vec()),
            IFLA_LINK => Link(payload.to_vec()),
            IFLA_QDISC => Qdisc(payload.to_vec()),
            IFLA_STATS => Stats(payload.to_vec()),
            // Mac address
            IFLA_ADDRESS => Address(parse_mac(payload)?),
            IFLA_BROADCAST => Broadcast(parse_mac(payload)?),
            // String
            IFLA_IFNAME => Ifname(parse_string(payload)?),
            // u8
            IFLA_OPERSTATE => OperState(parse_u8(payload)?),
            IFLA_LINKMODE => LinkMode(parse_u8(payload)?),
            // u32
            IFLA_MTU => Mtu(parse_u32(payload)?),
            IFLA_NUM_TX_QUEUES => NumTxQueues(parse_u32(payload)?),
            IFLA_PROMISCUITY => Promiscuity(parse_u32(payload)?),
            IFLA_GROUP => Group(parse_u32(payload)?),
            IFLA_TXQLEN => TxQueueLen(parse_u32(payload)?),
            // default attributes
            _ => Other(DefaultAttribute::from_packet(packet)?),
        })
    }
}

fn parse_mac(payload: &[u8]) -> Result<[u8; 6]> {
    if payload.len() != 6 {
        return Err(Error::MalformedAttributeValue);
    }
    let mut address: [u8; 6] = [0; 6];
    for (i, byte) in payload.into_iter().enumerate() {
        address[i] = *byte;
    }
    Ok(address)
}

fn parse_string(payload: &[u8]) -> Result<String> {
    if payload.is_empty() {
        return Ok(String::new());
    }
    let s = String::from_utf8(payload[..payload.len() - 1].to_vec())
        .map_err(|_| Error::MalformedAttributeValue)?;
    Ok(s)
}

fn parse_u8(payload: &[u8]) -> Result<u8> {
    if payload.len() != 1 {
        return Err(Error::MalformedAttributeValue);
    }
    Ok(payload[0])
}

fn parse_u32(payload: &[u8]) -> Result<u32> {
    if payload.len() != 4 {
        return Err(Error::MalformedAttributeValue);
    }
    Ok(NativeEndian::read_u32(payload))
}
