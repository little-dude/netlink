mod inet;
pub use self::inet::*;

mod inet6;
pub use self::inet6::*;

mod af_spec_inet;
pub use self::af_spec_inet::*;

mod link_infos;
pub use self::link_infos::*;

mod map;
pub use self::map::*;

mod stats;
pub use self::stats::*;

mod stats64;
pub use self::stats64::*;

mod link_state;
pub use self::link_state::*;

#[cfg(test)]
mod tests;

use std::mem::size_of;
use std::os::unix::io::RawFd;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{
    rtnl::{
        link::address_families::*,
        nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
        traits::{Emitable, Parseable, ParseableParametrized},
        utils::{parse_i32, parse_string, parse_u32, parse_u8},
    },
    DecodeError,
};

pub const IFLA_UNSPEC: u16 = 0;
pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_BROADCAST: u16 = 2;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_LINK: u16 = 5;
pub const IFLA_QDISC: u16 = 6;
pub const IFLA_STATS: u16 = 7;
pub const IFLA_COST: u16 = 8;
pub const IFLA_PRIORITY: u16 = 9;
pub const IFLA_MASTER: u16 = 10;
pub const IFLA_WIRELESS: u16 = 11;
pub const IFLA_PROTINFO: u16 = 12;
pub const IFLA_TXQLEN: u16 = 13;
pub const IFLA_MAP: u16 = 14;
pub const IFLA_WEIGHT: u16 = 15;
pub const IFLA_OPERSTATE: u16 = 16;
pub const IFLA_LINKMODE: u16 = 17;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_NET_NS_PID: u16 = 19;
pub const IFLA_IFALIAS: u16 = 20;
pub const IFLA_NUM_VF: u16 = 21;
pub const IFLA_VFINFO_LIST: u16 = 22;
pub const IFLA_STATS64: u16 = 23;
pub const IFLA_VF_PORTS: u16 = 24;
pub const IFLA_PORT_SELF: u16 = 25;
pub const IFLA_AF_SPEC: u16 = 26;
pub const IFLA_GROUP: u16 = 27;
pub const IFLA_NET_NS_FD: u16 = 28;
pub const IFLA_EXT_MASK: u16 = 29;
pub const IFLA_PROMISCUITY: u16 = 30;
pub const IFLA_NUM_TX_QUEUES: u16 = 31;
pub const IFLA_NUM_RX_QUEUES: u16 = 32;
pub const IFLA_CARRIER: u16 = 33;
pub const IFLA_PHYS_PORT_ID: u16 = 34;
pub const IFLA_CARRIER_CHANGES: u16 = 35;
pub const IFLA_PHYS_SWITCH_ID: u16 = 36;
pub const IFLA_LINK_NETNSID: u16 = 37;
pub const IFLA_PHYS_PORT_NAME: u16 = 38;
pub const IFLA_PROTO_DOWN: u16 = 39;
pub const IFLA_GSO_MAX_SEGS: u16 = 40;
pub const IFLA_GSO_MAX_SIZE: u16 = 41;
pub const IFLA_PAD: u16 = 42;
pub const IFLA_XDP: u16 = 43;
pub const IFLA_EVENT: u16 = 44;
pub const IFLA_NEW_NETNSID: u16 = 45;
pub const IFLA_IF_NETNSID: u16 = 46;
pub const IFLA_CARRIER_UP_COUNT: u16 = 47;
pub const IFLA_CARRIER_DOWN_COUNT: u16 = 48;
pub const IFLA_NEW_IFINDEX: u16 = 49;

pub const IFLA_INET_UNSPEC: u16 = 0;
pub const IFLA_INET_CONF: u16 = 1;

pub const IFLA_INET6_UNSPEC: u16 = 0;
pub const IFLA_INET6_FLAGS: u16 = 1;
pub const IFLA_INET6_CONF: u16 = 2;
pub const IFLA_INET6_STATS: u16 = 3;
// pub const IFLA_INET6_MCAST: u16 = 4;
pub const IFLA_INET6_CACHEINFO: u16 = 5;
pub const IFLA_INET6_ICMP6STATS: u16 = 6;
pub const IFLA_INET6_TOKEN: u16 = 7;
pub const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;

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
    NetNsFd(RawFd),
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
    Stats(Vec<u8>),
    Stats64(Vec<u8>),
    Map(Vec<u8>),
    // AF_SPEC (the type of af_spec depends on the interface family of the message)
    AfSpecInet(Vec<LinkAfSpecInetNla>),
    // AfSpecBridge(Vec<LinkAfSpecBridgeNla>),
    AfSpecBridge(Vec<u8>),
    AfSpecUnknown(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for LinkNla {
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
                | Wireless(ref bytes)
                | ProtoInfo(ref bytes)
                | CarrierUpCount(ref bytes)
                | CarrierDownCount(ref bytes)
                | NewIfIndex(ref bytes)
                | Address(ref bytes)
                | Broadcast(ref bytes)
                | AfSpecUnknown(ref bytes)
                | AfSpecBridge(ref bytes)
                | Map(ref bytes)
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
                | NetNsFd(_)
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
            Stats(_) => LINK_STATS_LEN,
            Stats64(_) => LINK_STATS64_LEN,
            LinkInfo(ref nlas) => nlas.as_slice().buffer_len(),
            AfSpecInet(ref nlas) => nlas.as_slice().buffer_len(),
            // AfSpecBridge(ref nlas) => nlas.as_slice().buffer_len(),
            Other(ref attr)  => attr.value_len(),
        }
    }

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
                | AfSpecUnknown(ref bytes)
                | AfSpecBridge(ref bytes)
                | Stats(ref bytes)
                | Stats64(ref bytes)
                | Map(ref bytes)
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
                | ExtMask(ref value)
                | Promiscuity(ref value)
                | NumTxQueues(ref value)
                | NumRxQueues(ref value)
                | CarrierChanges(ref value)
                | GsoMaxSegs(ref value)
                | GsoMaxSize(ref value)
                => NativeEndian::write_u32(buffer, *value),

            LinkNetnsId(ref value)
                | NetNsFd(ref value)
                => NativeEndian::write_i32(buffer, *value),

            OperState(state) => buffer[0] = state.into(),
            LinkInfo(ref nlas) => nlas.as_slice().emit(buffer),
            AfSpecInet(ref nlas) => nlas.as_slice().emit(buffer),
            // AfSpecBridge(ref nlas) => nlas.as_slice().emit(buffer),
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
            NetNsFd(_) => IFLA_NET_NS_FD,
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
            AfSpecInet(_) | AfSpecBridge(_) | AfSpecUnknown(_) => IFLA_AF_SPEC,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> ParseableParametrized<LinkNla, u16>
    for NlaBuffer<&'buffer T>
{
    fn parse_with_param(&self, interface_family: u16) -> Result<LinkNla, DecodeError> {
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
            IFLA_IFNAME => IfName(parse_string(payload).context("invalid IFLA_IFNAME value")?),
            IFLA_QDISC => Qdisc(parse_string(payload).context("invalid IFLA_QDISC value")?),
            IFLA_IFALIAS => IfAlias(parse_string(payload).context("invalid IFLA_IFALIAS value")?),
            IFLA_PHYS_PORT_NAME => {
                PhysPortName(parse_string(payload).context("invalid IFLA_PHYS_PORT_NAME value")?)
            }

            // u8
            IFLA_LINKMODE => LinkMode(parse_u8(payload).context("invalid IFLA_LINKMODE value")?),
            IFLA_CARRIER => Carrier(parse_u8(payload).context("invalid IFLA_CARRIER value")?),
            IFLA_PROTO_DOWN => {
                ProtoDown(parse_u8(payload).context("invalid IFLA_PROTO_DOWN value")?)
            }

            // u32
            IFLA_MTU => Mtu(parse_u32(payload).context("invalid IFLA_MTU value")?),
            IFLA_LINK => Link(parse_u32(payload).context("invalid IFLA_LINK value")?),
            IFLA_MASTER => Master(parse_u32(payload).context("invalid IFLA_MASTER value")?),
            IFLA_TXQLEN => TxQueueLen(parse_u32(payload).context("invalid IFLA_TXQLEN value")?),
            IFLA_NET_NS_PID => {
                NetNsPid(parse_u32(payload).context("invalid IFLA_NET_NS_PID value")?)
            }
            IFLA_NUM_VF => NumVf(parse_u32(payload).context("invalid IFLA_NUM_VF value")?),
            IFLA_GROUP => Group(parse_u32(payload).context("invalid IFLA_GROUP value")?),
            IFLA_NET_NS_FD => NetNsFd(parse_i32(payload).context("invalid IFLA_NET_NS_FD value")?),
            IFLA_EXT_MASK => ExtMask(parse_u32(payload).context("invalid IFLA_EXT_MASK value")?),
            IFLA_PROMISCUITY => {
                Promiscuity(parse_u32(payload).context("invalid IFLA_PROMISCUITY value")?)
            }
            IFLA_NUM_TX_QUEUES => {
                NumTxQueues(parse_u32(payload).context("invalid IFLA_NUM_TX_QUEUES value")?)
            }
            IFLA_NUM_RX_QUEUES => {
                NumRxQueues(parse_u32(payload).context("invalid IFLA_NUM_RX_QUEUES value")?)
            }
            IFLA_CARRIER_CHANGES => {
                CarrierChanges(parse_u32(payload).context("invalid IFLA_CARRIER_CHANGES value")?)
            }
            IFLA_GSO_MAX_SEGS => {
                GsoMaxSegs(parse_u32(payload).context("invalid IFLA_GSO_MAX_SEGS value")?)
            }
            IFLA_GSO_MAX_SIZE => {
                GsoMaxSize(parse_u32(payload).context("invalid IFLA_GSO_MAX_SIZE value")?)
            }

            // i32
            IFLA_LINK_NETNSID => {
                LinkNetnsId(parse_i32(payload).context("invalid IFLA_LINK_NETNSID value")?)
            }

            IFLA_OPERSTATE => OperState(
                parse_u8(payload)
                    .context("invalid IFLA_OPERSTATE value")?
                    .into(),
            ),
            IFLA_MAP => Map(payload.to_vec()),
            IFLA_STATS => Stats(payload.to_vec()),
            IFLA_STATS64 => Stats64(payload.to_vec()),
            IFLA_AF_SPEC => match interface_family as u16 {
                AF_INET | AF_INET6 | AF_UNSPEC => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(payload) {
                        let nla = nla.context("invalid IFLA_AF_SPEC value")?;
                        nlas.push(
                            <dyn Parseable<LinkAfSpecInetNla>>::parse(&nla)
                                .context("invalid IFLA_AF_SPEC value")?,
                        );
                    }
                    AfSpecInet(nlas)
                }
                AF_BRIDGE => AfSpecBridge(payload.to_vec()),
                _ => AfSpecUnknown(payload.to_vec()),
            },

            IFLA_LINKINFO => LinkInfo(
                NlaBuffer::new_checked(payload)
                    .context("invalid IFLA_LINKINFO value")?
                    .parse()
                    .context("invalid IFLA_LINKINFO value")?,
            ),
            // default nlas
            _ => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context("invalid link NLA value (unknown type)")?,
            ),
        })
    }
}
