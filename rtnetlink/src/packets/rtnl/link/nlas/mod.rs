mod inet;
pub use self::inet::*;

mod inet6;
pub use self::inet6::*;

mod af_spec;
pub use self::af_spec::*;

mod link_infos;
pub use self::link_infos::*;

#[cfg(test)]
mod tests;

use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};

use constants::*;
use utils::{parse_i32, parse_string, parse_u32, parse_u8};
use {DefaultNla, Emitable, NativeNla, Nla, NlaBuffer, Parseable, Result};

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
    LinkInfo(Vec<LinkInfo>),
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
    OperState(LinkState),
    Stats(LinkStats32),
    Stats64(LinkStats64),
    Map(LinkMap),
    // AF_SPEC
    AfSpec(LinkAfSpecNla),
    Other(DefaultNla),
}

impl Nla for LinkNla {
    #[cfg_attr(nightly, rustfmt::skip)]
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
                | Wireless(ref bytes)
                | ProtoInfo(ref bytes)
                | CarrierUpCount(ref bytes)
                | CarrierDownCount(ref bytes)
                | NewIfIndex(ref bytes)
                | Address(ref bytes)
                | Broadcast(ref bytes)
                => bytes.len(),

            // strings: +1 because we need to append a nul byte
            IfName(ref string)
                | Qdisc(ref string)
                | IfAlias(ref string)
                | PhysPortName(ref string)
                => string.as_bytes().len() + 1,

            // u8
            LinkMode(_)
                | Carrier(_)
                | ProtoDown(_)
                => size_of::<u8>(),

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
            OperState(_) => size_of::<u8>(),
            Map(_) => size_of::<LinkMap>(),
            Stats(_) => size_of::<LinkStats32>(),
            Stats64(_) => size_of::<LinkStats64>(),
            LinkInfo(ref nlas) => nlas.as_slice().buffer_len(),
            AfSpec(ref af_spec) => af_spec.buffer_len(),
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
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
                | Broadcast(ref bytes)
                => buffer.copy_from_slice(bytes.as_slice()),

            // String
            IfName(ref string)
                | Qdisc(ref string)
                | IfAlias(ref string)
                | PhysPortName(ref string)
                => {
                    buffer[..string.len()].copy_from_slice(string.as_bytes());
                    buffer[string.len()] = 0;
                }

            // u8
            LinkMode(ref val)
                | Carrier(ref val)
                | ProtoDown(ref val)
                => buffer[0] = *val,

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
                | GsoMaxSize(ref value)
                => NativeEndian::write_u32(buffer, *value),

            LinkNetnsId(ref value) => NativeEndian::write_i32(buffer, *value),

            OperState(state) => buffer[0] = state.into(),
            Map(ref map) => map.to_bytes(buffer),
            Stats(ref stats) => stats.to_bytes(buffer),
            Stats64(ref stats) => stats.to_bytes(buffer),
            LinkInfo(ref nlas) => nlas.as_slice().emit(buffer),
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
            OperState(_) => IFLA_OPERSTATE,
            Map(_) => IFLA_MAP,
            Stats(_) => IFLA_STATS,
            Stats64(_) => IFLA_STATS64,
            AfSpec(_) => IFLA_AF_SPEC,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkNla> for NlaBuffer<&'buffer T> {
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

            IFLA_OPERSTATE => OperState(parse_u8(payload)?.into()),
            IFLA_MAP => Map(LinkMap::from_bytes(payload)?),
            IFLA_STATS => Stats(LinkStats32::from_bytes(payload)?),
            IFLA_STATS64 => Stats64(LinkStats64::from_bytes(payload)?),
            IFLA_AF_SPEC => AfSpec(NlaBuffer::new_checked(payload)?.parse()?),

            IFLA_LINKINFO => LinkInfo(NlaBuffer::new_checked(payload)?.parse()?),
            // default nlas
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LinkMap {
    pub memory_start: u64,
    pub memory_end: u64,
    pub base_address: u64,
    pub irq: u16,
    pub dma: u8,
    pub port: u8,
}

impl NativeNla for LinkMap {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LinkStats<T> {
    /// total packets received
    pub rx_packets: T,
    /// total packets transmitted
    pub tx_packets: T,
    /// total bytes received
    pub rx_bytes: T,
    /// total bytes transmitted
    pub tx_bytes: T,
    /// bad packets received
    pub rx_errors: T,
    /// packet transmit problems
    pub tx_errors: T,
    /// no space in linux buffers
    pub rx_dropped: T,
    /// no space available in linux
    pub tx_dropped: T,
    /// multicast packets received
    pub multicast: T,
    pub collisions: T,

    // detailed rx_errors
    pub rx_length_errors: T,
    /// receiver ring buff overflow
    pub rx_over_errors: T,
    /// received packets with crc error
    pub rx_crc_errors: T,
    /// received frame alignment errors
    pub rx_frame_errors: T,
    /// recv'r fifo overrun
    pub rx_fifo_errors: T,
    /// receiver missed packet
    pub rx_missed_errors: T,

    // detailed tx_errors
    pub tx_aborted_errors: T,
    pub tx_carrier_errors: T,
    pub tx_fifo_errors: T,
    pub tx_heartbeat_errors: T,
    pub tx_window_errors: T,

    // for cslip etc
    pub rx_compressed: T,
    pub tx_compressed: T,

    /// dropped, no handler found
    pub rx_nohandler: T,
}

impl NativeNla for LinkStats<u32> {}
impl NativeNla for LinkStats<u64> {}

pub type LinkStats32 = LinkStats<u32>;
pub type LinkStats64 = LinkStats<u64>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LinkState {
    /// Status can't be determined
    Unknown,
    /// Some component is missing
    NotPresent,
    /// Down
    Down,
    /// Down due to state of lower layer
    LowerLayerDown,
    /// In some test mode
    Testing,
    /// Not up but pending an external event
    Dormant,
    /// Up, ready to send packets
    Up,
    /// Unrecognized value. This should go away when `TryFrom` is stable in Rust
    // FIXME: there's not point in having this. When TryFrom is stable we'll remove it
    Other(u8),
}

impl From<u8> for LinkState {
    fn from(value: u8) -> Self {
        use self::LinkState::*;
        match value {
            IF_OPER_UNKNOWN => Unknown,
            IF_OPER_NOTPRESENT => NotPresent,
            IF_OPER_DOWN => Down,
            IF_OPER_LOWERLAYERDOWN => LowerLayerDown,
            IF_OPER_TESTING => Testing,
            IF_OPER_DORMANT => Dormant,
            IF_OPER_UP => Up,
            _ => Other(value),
        }
    }
}

impl From<LinkState> for u8 {
    fn from(value: LinkState) -> Self {
        use self::LinkState::*;
        match value {
            Unknown => IF_OPER_UNKNOWN,
            NotPresent => IF_OPER_NOTPRESENT,
            Down => IF_OPER_DOWN,
            LowerLayerDown => IF_OPER_LOWERLAYERDOWN,
            Testing => IF_OPER_TESTING,
            Dormant => IF_OPER_DORMANT,
            Up => IF_OPER_UP,
            Other(other) => other,
        }
    }
}
