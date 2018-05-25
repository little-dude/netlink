use byteorder::{ByteOrder, NativeEndian};
use constants;
use packet::common::nla::{
    parse_i32, parse_string, parse_u32, parse_u8, DefaultNla, NativeNla, Nla, NlaBuffer,
};
use packet::common::{Emitable, Parseable, Result};
use packet::rtnl::link::{af_spec, map, stats};
use std::mem::size_of;

pub const IFLA_UNSPEC: u16 = constants::IFLA_UNSPEC as u16;
pub const IFLA_ADDRESS: u16 = constants::IFLA_ADDRESS as u16;
pub const IFLA_BROADCAST: u16 = constants::IFLA_BROADCAST as u16;
pub const IFLA_IFNAME: u16 = constants::IFLA_IFNAME as u16;
pub const IFLA_MTU: u16 = constants::IFLA_MTU as u16;
pub const IFLA_LINK: u16 = constants::IFLA_LINK as u16;
pub const IFLA_QDISC: u16 = constants::IFLA_QDISC as u16;
pub const IFLA_STATS: u16 = constants::IFLA_STATS as u16;
pub const IFLA_COST: u16 = constants::IFLA_COST as u16;
pub const IFLA_PRIORITY: u16 = constants::IFLA_PRIORITY as u16;
pub const IFLA_MASTER: u16 = constants::IFLA_MASTER as u16;
// TODO: implement custom parsing for this struct
pub const IFLA_WIRELESS: u16 = constants::IFLA_WIRELESS as u16;
// TODO: implement custom parsing for this struct
pub const IFLA_PROTINFO: u16 = constants::IFLA_PROTINFO as u16;
pub const IFLA_TXQLEN: u16 = constants::IFLA_TXQLEN as u16;
pub const IFLA_MAP: u16 = constants::IFLA_MAP as u16;
pub const IFLA_WEIGHT: u16 = constants::IFLA_WEIGHT as u16;
pub const IFLA_OPERSTATE: u16 = constants::IFLA_OPERSTATE as u16;
pub const IFLA_LINKMODE: u16 = constants::IFLA_LINKMODE as u16;
// TODO: implement custom parsing for this struct
pub const IFLA_LINKINFO: u16 = constants::IFLA_LINKINFO as u16;
pub const IFLA_NET_NS_PID: u16 = constants::IFLA_NET_NS_PID as u16;
pub const IFLA_IFALIAS: u16 = constants::IFLA_IFALIAS as u16;
pub const IFLA_NUM_VF: u16 = constants::IFLA_NUM_VF as u16;
pub const IFLA_VFINFO_LIST: u16 = constants::IFLA_VFINFO_LIST as u16;
pub const IFLA_STATS64: u16 = constants::IFLA_STATS64 as u16;
pub const IFLA_VF_PORTS: u16 = constants::IFLA_VF_PORTS as u16;
pub const IFLA_PORT_SELF: u16 = constants::IFLA_PORT_SELF as u16;
pub const IFLA_AF_SPEC: u16 = constants::IFLA_AF_SPEC as u16;
pub const IFLA_GROUP: u16 = constants::IFLA_GROUP as u16;
pub const IFLA_NET_NS_FD: u16 = constants::IFLA_NET_NS_FD as u16;
pub const IFLA_EXT_MASK: u16 = constants::IFLA_EXT_MASK as u16;
pub const IFLA_PROMISCUITY: u16 = constants::IFLA_PROMISCUITY as u16;
pub const IFLA_NUM_TX_QUEUES: u16 = constants::IFLA_NUM_TX_QUEUES as u16;
pub const IFLA_NUM_RX_QUEUES: u16 = constants::IFLA_NUM_RX_QUEUES as u16;
pub const IFLA_CARRIER: u16 = constants::IFLA_CARRIER as u16;
pub const IFLA_PHYS_PORT_ID: u16 = constants::IFLA_PHYS_PORT_ID as u16;
pub const IFLA_CARRIER_CHANGES: u16 = constants::IFLA_CARRIER_CHANGES as u16;
pub const IFLA_PHYS_SWITCH_ID: u16 = constants::IFLA_PHYS_SWITCH_ID as u16;
pub const IFLA_LINK_NETNSID: u16 = constants::IFLA_LINK_NETNSID as u16;
pub const IFLA_PHYS_PORT_NAME: u16 = constants::IFLA_PHYS_PORT_NAME as u16;
pub const IFLA_PROTO_DOWN: u16 = constants::IFLA_PROTO_DOWN as u16;
pub const IFLA_GSO_MAX_SEGS: u16 = constants::IFLA_GSO_MAX_SEGS as u16;
pub const IFLA_GSO_MAX_SIZE: u16 = constants::IFLA_GSO_MAX_SIZE as u16;
pub const IFLA_PAD: u16 = constants::IFLA_PAD as u16;
pub const IFLA_XDP: u16 = constants::IFLA_XDP as u16;
pub const IFLA_EVENT: u16 = constants::IFLA_EVENT as u16;
pub const IFLA_NEW_NETNSID: u16 = constants::IFLA_NEW_NETNSID as u16;
pub const IFLA_IF_NETNSID: u16 = constants::IFLA_IF_NETNSID as u16;
pub const IFLA_CARRIER_UP_COUNT: u16 = constants::IFLA_CARRIER_UP_COUNT as u16;
pub const IFLA_CARRIER_DOWN_COUNT: u16 = constants::IFLA_CARRIER_DOWN_COUNT as u16;
pub const IFLA_NEW_IFINDEX: u16 = constants::IFLA_NEW_IFINDEX as u16;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkNla {
    // Vec<u8>
    Unspec(Vec<u8>),
    Cost(Vec<u8>),
    Priority(Vec<u8>),
    Weight(Vec<u8>),
    VfInfoList(Vec<u8>),
    VfPorts(Vec<u8>),
    PortSelf(Vec<u8>),
    PhysPortId(Vec<u8>),
    PhysSwitchId(Vec<u8>),
    Pad(Vec<u8>),
    Xdp(Vec<u8>),
    Event(Vec<u8>),
    NewNetnsId(Vec<u8>),
    IfNetnsId(Vec<u8>),
    CarrierUpCount(Vec<u8>),
    CarrierDownCount(Vec<u8>),
    NewIfIndex(Vec<u8>),
    LinkInfo(Vec<u8>),
    Wireless(Vec<u8>),
    ProtoInfo(Vec<u8>),
    // mac address (use to be [u8; 6] but it turns out MAC != HW address, for instance for IP over
    // GRE where it's an IPv4!)
    Address(Vec<u8>),
    Broadcast(Vec<u8>),

    // string
    // FIXME: for empty string, should we encode the NLA as \0 or should we not set a payload? It
    // seems that for certain attriutes, this matter:
    // https://elixir.bootlin.com/linux/v4.17-rc5/source/net/core/rtnetlink.c#L1660
    IfName(String),
    Qdisc(String),
    IfAlias(String),
    PhysPortName(String),
    // byte
    OperState(u8),
    LinkMode(u8),
    Carrier(u8),
    ProtoDown(u8),
    // u32
    Mtu(u32),
    Link(u32),
    Master(u32),
    TxQueueLen(u32),
    NetNsPid(u32),
    NumVf(u32),
    Group(u32),
    NetnsFd(u32),
    ExtMask(u32),
    Promiscuity(u32),
    NumTxQueues(u32),
    NumRxQueues(u32),
    CarrierChanges(u32),
    GsoMaxSegs(u32),
    GsoMaxSize(u32),
    // i32
    LinkNetnsId(i32),
    // custom
    Stats(stats::Stats32),
    Stats64(stats::Stats64),
    Map(map::Map),
    // AF_SPEC
    AfSpec(af_spec::AfSpec),
    Other(DefaultNla),
}

impl Nla for LinkNla {
    #[allow(unused_attributes)]
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::LinkNla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Cost(ref bytes)
                | Priority(ref bytes)
                | Weight(ref bytes)
                | VfInfoList(ref bytes)
                | VfPorts(ref bytes)
                | PortSelf(ref bytes)
                | PhysPortId(ref bytes)
                | PhysSwitchId(ref bytes)
                | Pad(ref bytes)
                | Xdp(ref bytes)
                | Event(ref bytes)
                | NewNetnsId(ref bytes)
                | IfNetnsId(ref bytes)
                | LinkInfo(ref bytes)
                | Wireless(ref bytes)
                | ProtoInfo(ref bytes)
                | CarrierUpCount(ref bytes)
                | CarrierDownCount(ref bytes)
                | NewIfIndex(ref bytes)
                | Address(ref bytes)
                | Broadcast(ref bytes) => bytes.len(),

            // strings: +1 because we need to append a nul byte
            IfName(ref string)
                | Qdisc(ref string)
                | IfAlias(ref string)
                | PhysPortName(ref string) => string.as_bytes().len() + 1,

            // Mac addresses are arrays of 6 bytes

            // u8
            OperState(_)
                | LinkMode(_)
                | Carrier(_)
                | ProtoDown(_) => size_of::<u8>(),

            // u32 and i32
            Mtu(_)
                | Link(_)
                | Master(_)
                | TxQueueLen(_)
                | NetNsPid(_)
                | NumVf(_)
                | Group(_)
                | NetnsFd(_)
                | ExtMask(_)
                | Promiscuity(_)
                | NumTxQueues(_)
                | NumRxQueues(_)
                | CarrierChanges(_)
                | GsoMaxSegs(_)
                | GsoMaxSize(_)
                | LinkNetnsId(_) => size_of::<u32>(),

            // Defaults
            Map(_) => size_of::<map::Map>(),
            Stats(_) => size_of::<stats::Stats32>(),
            Stats64(_) => size_of::<stats::Stats64>(),
            AfSpec(ref af_spec) => af_spec.value_len(),
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[allow(unused_attributes)]
    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkNla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Cost(ref bytes)
                | Priority(ref bytes)
                | Weight(ref bytes)
                | VfInfoList(ref bytes)
                | VfPorts(ref bytes)
                | PortSelf(ref bytes)
                | PhysPortId(ref bytes)
                | PhysSwitchId(ref bytes)
                | LinkInfo(ref bytes)
                | Wireless(ref bytes)
                | ProtoInfo(ref bytes)
                | Pad(ref bytes)
                | Xdp(ref bytes)
                | Event(ref bytes)
                | NewNetnsId(ref bytes)
                | IfNetnsId(ref bytes)
                | CarrierUpCount(ref bytes)
                | CarrierDownCount(ref bytes)
                | NewIfIndex(ref bytes)
                // mac address (could be [u8; 6] or [u8; 4] for example. Not sure if we should have
                // a separate type for them
                | Address(ref bytes)
                | Broadcast(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            // String
            IfName(ref string)
                | Qdisc(ref string)
                | IfAlias(ref string)
                | PhysPortName(ref string) => {
                    buffer.copy_from_slice(string.as_bytes());
                    buffer[string.as_bytes().len()] = 0;
                }

            // u8
            OperState(ref val)
                | LinkMode(ref val)
                | Carrier(ref val)
                | ProtoDown(ref val) => buffer[0] = *val,

            // u32
            Mtu(ref value)
                | Link(ref value)
                | Master(ref value)
                | TxQueueLen(ref value)
                | NetNsPid(ref value)
                | NumVf(ref value)
                | Group(ref value)
                | NetnsFd(ref value)
                | ExtMask(ref value)
                | Promiscuity(ref value)
                | NumTxQueues(ref value)
                | NumRxQueues(ref value)
                | CarrierChanges(ref value)
                | GsoMaxSegs(ref value)
                | GsoMaxSize(ref value) => NativeEndian::write_u32(buffer, *value),

            LinkNetnsId(ref value) => NativeEndian::write_i32(buffer, *value),

            Map(ref map) => map.to_bytes(buffer),
            Stats(ref stats) => stats.to_bytes(buffer),
            Stats64(ref stats) => stats.to_bytes(buffer),
            // This is not supposed to fail, because the buffer length has normally been checked
            // before cally this method. If that fails, there's a bug in out code that needs to be
            // fixed.
            AfSpec(ref af_spec) => af_spec.emit(buffer),
            // default nlas
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkNla::*;
        match *self {
            // Vec<u8>
            Unspec(_) => IFLA_UNSPEC,
            Cost(_) => IFLA_COST,
            Priority(_) => IFLA_PRIORITY,
            Weight(_) => IFLA_WEIGHT,
            VfInfoList(_) => IFLA_VFINFO_LIST,
            VfPorts(_) => IFLA_VF_PORTS,
            PortSelf(_) => IFLA_PORT_SELF,
            PhysPortId(_) => IFLA_PHYS_PORT_ID,
            PhysSwitchId(_) => IFLA_PHYS_SWITCH_ID,
            LinkInfo(_) => IFLA_LINKINFO,
            Wireless(_) => IFLA_WIRELESS,
            ProtoInfo(_) => IFLA_PROTINFO,
            Pad(_) => IFLA_PAD,
            Xdp(_) => IFLA_XDP,
            Event(_) => IFLA_EVENT,
            NewNetnsId(_) => IFLA_NEW_NETNSID,
            IfNetnsId(_) => IFLA_IF_NETNSID,
            CarrierUpCount(_) => IFLA_CARRIER_UP_COUNT,
            CarrierDownCount(_) => IFLA_CARRIER_DOWN_COUNT,
            NewIfIndex(_) => IFLA_NEW_IFINDEX,
            // Mac address
            Address(_) => IFLA_ADDRESS,
            Broadcast(_) => IFLA_BROADCAST,
            // String
            IfName(_) => IFLA_IFNAME,
            Qdisc(_) => IFLA_QDISC,
            IfAlias(_) => IFLA_IFALIAS,
            PhysPortName(_) => IFLA_PHYS_PORT_NAME,
            // u8
            OperState(_) => IFLA_OPERSTATE,
            LinkMode(_) => IFLA_LINKMODE,
            Carrier(_) => IFLA_CARRIER,
            ProtoDown(_) => IFLA_PROTO_DOWN,
            // u32
            Mtu(_) => IFLA_MTU,
            Link(_) => IFLA_LINK,
            Master(_) => IFLA_MASTER,
            TxQueueLen(_) => IFLA_TXQLEN,
            NetNsPid(_) => IFLA_NET_NS_PID,
            NumVf(_) => IFLA_NUM_VF,
            Group(_) => IFLA_GROUP,
            NetnsFd(_) => IFLA_NET_NS_FD,
            ExtMask(_) => IFLA_EXT_MASK,
            Promiscuity(_) => IFLA_PROMISCUITY,
            NumTxQueues(_) => IFLA_NUM_TX_QUEUES,
            NumRxQueues(_) => IFLA_NUM_RX_QUEUES,
            CarrierChanges(_) => IFLA_CARRIER_CHANGES,
            GsoMaxSegs(_) => IFLA_GSO_MAX_SEGS,
            GsoMaxSize(_) => IFLA_GSO_MAX_SIZE,
            // i32
            LinkNetnsId(_) => IFLA_LINK_NETNSID,
            // custom
            Map(_) => IFLA_MAP,
            Stats(_) => IFLA_STATS,
            Stats64(_) => IFLA_STATS64,
            AfSpec(_) => IFLA_AF_SPEC,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkNla> for NlaBuffer<&'buffer T> {
    /// # Panic
    ///
    /// This panics on buffers for which the "length" field value is is wrong. The
    /// `NlaBuffer` argument must be checked before being passed to this method.
    fn parse(&self) -> Result<LinkNla> {
        use self::LinkNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            // Vec<u8>
            IFLA_UNSPEC => Unspec(payload.to_vec()),
            IFLA_COST => Cost(payload.to_vec()),
            IFLA_PRIORITY => Priority(payload.to_vec()),
            IFLA_WEIGHT => Weight(payload.to_vec()),
            IFLA_VFINFO_LIST => VfInfoList(payload.to_vec()),
            IFLA_VF_PORTS => VfPorts(payload.to_vec()),
            IFLA_PORT_SELF => PortSelf(payload.to_vec()),
            IFLA_PHYS_PORT_ID => PhysPortId(payload.to_vec()),
            IFLA_PHYS_SWITCH_ID => PhysSwitchId(payload.to_vec()),
            IFLA_LINKINFO => LinkInfo(payload.to_vec()),
            IFLA_WIRELESS => Wireless(payload.to_vec()),
            IFLA_PROTINFO => ProtoInfo(payload.to_vec()),
            IFLA_PAD => Pad(payload.to_vec()),
            IFLA_XDP => Xdp(payload.to_vec()),
            IFLA_EVENT => Event(payload.to_vec()),
            IFLA_NEW_NETNSID => NewNetnsId(payload.to_vec()),
            IFLA_IF_NETNSID => IfNetnsId(payload.to_vec()),
            IFLA_CARRIER_UP_COUNT => CarrierUpCount(payload.to_vec()),
            IFLA_CARRIER_DOWN_COUNT => CarrierDownCount(payload.to_vec()),
            IFLA_NEW_IFINDEX => NewIfIndex(payload.to_vec()),
            // HW address (we parse them as Vec for now, because for IP over GRE, the HW address is
            // an IP instead of a MAC for example
            IFLA_ADDRESS => Address(payload.to_vec()),
            IFLA_BROADCAST => Broadcast(payload.to_vec()),
            // String
            IFLA_IFNAME => IfName(parse_string(payload)?),
            IFLA_QDISC => Qdisc(parse_string(payload)?),
            IFLA_IFALIAS => IfAlias(parse_string(payload)?),
            IFLA_PHYS_PORT_NAME => PhysPortName(parse_string(payload)?),

            // u8
            IFLA_OPERSTATE => OperState(parse_u8(payload)?),
            IFLA_LINKMODE => LinkMode(parse_u8(payload)?),
            IFLA_CARRIER => Carrier(parse_u8(payload)?),
            IFLA_PROTO_DOWN => ProtoDown(parse_u8(payload)?),

            // u32
            IFLA_MTU => Mtu(parse_u32(payload)?),
            IFLA_LINK => Link(parse_u32(payload)?),
            IFLA_MASTER => Master(parse_u32(payload)?),
            IFLA_TXQLEN => TxQueueLen(parse_u32(payload)?),
            IFLA_NET_NS_PID => NetNsPid(parse_u32(payload)?),
            IFLA_NUM_VF => NumVf(parse_u32(payload)?),
            IFLA_GROUP => Group(parse_u32(payload)?),
            IFLA_NET_NS_FD => NetnsFd(parse_u32(payload)?),
            IFLA_EXT_MASK => ExtMask(parse_u32(payload)?),
            IFLA_PROMISCUITY => Promiscuity(parse_u32(payload)?),
            IFLA_NUM_TX_QUEUES => NumTxQueues(parse_u32(payload)?),
            IFLA_NUM_RX_QUEUES => NumRxQueues(parse_u32(payload)?),
            IFLA_CARRIER_CHANGES => CarrierChanges(parse_u32(payload)?),
            IFLA_GSO_MAX_SEGS => GsoMaxSegs(parse_u32(payload)?),
            IFLA_GSO_MAX_SIZE => GsoMaxSize(parse_u32(payload)?),

            // i32
            IFLA_LINK_NETNSID => LinkNetnsId(parse_i32(payload)?),

            IFLA_MAP => Map(map::Map::from_bytes(payload)?),
            IFLA_STATS => Stats(stats::Stats32::from_bytes(payload)?),
            IFLA_AF_SPEC => AfSpec(<Self as Parseable<af_spec::AfSpec>>::parse(self)?),
            // default nlas
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}
