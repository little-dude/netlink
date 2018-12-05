use byteorder::{ByteOrder, NativeEndian};
use constants::*;
use packets::rtnl::{LinkBuffer, LinkHeader, LinkMessage, LinkNla};
use std::mem::size_of;
use utils::{parse_mac, parse_string, parse_u16, parse_u32, parse_u64, parse_u8};
use {DefaultNla, Emitable, Error, Nla, NlaBuffer, NlasIterator, Parseable, Result};

const DUMMY: &str = "dummy";
const IFB: &str = "ifb";
const BRIDGE: &str = "bridge";
const TUN: &str = "tun";
const NLMON: &str = "nlmon";
const VLAN: &str = "vlan";
const VETH: &str = "veth";
const VXLAN: &str = "vxlan";
const BOND: &str = "bond";
const IPVLAN: &str = "ipvlan";
const MACVLAN: &str = "macvlan";
const MACVTAP: &str = "macvtap";
const GRETAP: &str = "gretap";
const IP6GRETAP: &str = "ip6gretap";
const IPIP: &str = "ipip";
const SIT: &str = "sit";
const GRE: &str = "gre";
const IP6GRE: &str = "ip6gre";
const VTI: &str = "vti";
const VRF: &str = "vrf";
const GTP: &str = "gtp";

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkInfo {
    Unspec(Vec<u8>),
    Xstats(Vec<u8>),
    Kind(LinkInfoKind),
    Data(LinkInfoData),
    SlaveKind(Vec<u8>),
    SlaveData(Vec<u8>),
}

impl Nla for LinkInfo {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::LinkInfo::*;
        match self {
            Unspec(ref bytes)
                | Xstats(ref bytes)
                | SlaveKind(ref bytes)
                | SlaveData(ref bytes)
                => bytes.len(),
            Kind(ref nla) => nla.value_len(),
            Data(ref nla) => nla.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkInfo::*;
        match self {
            Unspec(ref bytes)
                | Xstats(ref bytes)
                | SlaveKind(ref bytes)
                | SlaveData(ref bytes)
                => buffer.copy_from_slice(bytes),
            Kind(ref nla) => nla.emit_value(buffer),
            Data(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkInfo::*;
        match self {
            Unspec(_) => IFLA_INFO_UNSPEC,
            Xstats(_) => IFLA_INFO_XSTATS,
            SlaveKind(_) => IFLA_INFO_SLAVE_KIND,
            SlaveData(_) => IFLA_INFO_DATA,
            Kind(_) => IFLA_INFO_KIND,
            Data(_) => IFLA_INFO_DATA,
        }
    }
}

// XXX: we cannot impl Parseable<LinkInfo> because some attributes depend on each other. To parse
// IFLA_INFO_DATA we first need to parse the preceding IFLA_INFO_KIND for example.
impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<Vec<LinkInfo>> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<LinkInfo>> {
        let mut res = Vec::new();
        let nlas = NlasIterator::new(self.into_inner());
        let mut link_info_kind: Option<LinkInfoKind> = None;
        for nla in nlas {
            let nla = nla?;
            match nla.kind() {
                IFLA_INFO_UNSPEC => res.push(LinkInfo::Unspec(nla.value().to_vec())),
                IFLA_INFO_XSTATS => res.push(LinkInfo::Xstats(nla.value().to_vec())),
                IFLA_INFO_SLAVE_KIND => res.push(LinkInfo::SlaveKind(nla.value().to_vec())),
                IFLA_INFO_SLAVE_DATA => res.push(LinkInfo::SlaveData(nla.value().to_vec())),
                IFLA_INFO_KIND => {
                    let parsed = <NlaBuffer<_> as Parseable<LinkInfoKind>>::parse(&nla)?;
                    res.push(LinkInfo::Kind(parsed.clone()));
                    link_info_kind = Some(parsed);
                }
                IFLA_INFO_DATA => {
                    if let Some(link_info_kind) = link_info_kind {
                        let payload = nla.value();
                        let info_data = match link_info_kind {
                            LinkInfoKind::Dummy => LinkInfoData::Dummy(payload.to_vec()),
                            LinkInfoKind::Ifb => LinkInfoData::Ifb(payload.to_vec()),
                            LinkInfoKind::Bridge => {
                                let mut v = Vec::new();
                                for nla in NlasIterator::new(payload) {
                                    v.push(<NlaBuffer<_> as Parseable<LinkInfoBridge>>::parse(
                                        &nla?,
                                    )?);
                                }
                                LinkInfoData::Bridge(v)
                            }
                            LinkInfoKind::Vlan => {
                                let mut v = Vec::new();
                                for nla in NlasIterator::new(payload) {
                                    v.push(<NlaBuffer<_> as Parseable<LinkInfoVlan>>::parse(
                                        &nla?,
                                    )?);
                                }
                                LinkInfoData::Vlan(v)
                            }
                            LinkInfoKind::Tun => LinkInfoData::Tun(payload.to_vec()),
                            LinkInfoKind::Nlmon => LinkInfoData::Nlmon(payload.to_vec()),
                            LinkInfoKind::Veth => {
                                let buffer = LinkBuffer::new(&payload);
                                let header =
                                    <LinkBuffer<_> as Parseable<LinkHeader>>::parse(&buffer)?;

                                let parsed_nlas =
                                    <LinkBuffer<_> as Parseable<Vec<Result<LinkNla>>>>::parse(
                                        &buffer,
                                    )?;
                                let (valid_nlas, parse_errors): (Vec<_>, Vec<_>) =
                                    parsed_nlas.into_iter().partition(Result::is_ok);
                                let nlas = valid_nlas.into_iter().map(Result::unwrap).collect();

                                for parse_result in parse_errors {
                                    warn!(
                                        "Failed to parse a Netlink Link attribute: {}",
                                        parse_result.unwrap_err()
                                    );
                                }

                                LinkInfoData::Veth(LinkMessage::from_parts(header, nlas))
                            }
                            LinkInfoKind::Vxlan => LinkInfoData::Vxlan(payload.to_vec()),
                            LinkInfoKind::Bond => LinkInfoData::Bond(payload.to_vec()),
                            LinkInfoKind::IpVlan => LinkInfoData::IpVlan(payload.to_vec()),
                            LinkInfoKind::MacVlan => LinkInfoData::MacVlan(payload.to_vec()),
                            LinkInfoKind::MacVtap => LinkInfoData::MacVtap(payload.to_vec()),
                            LinkInfoKind::GreTap => LinkInfoData::GreTap(payload.to_vec()),
                            LinkInfoKind::GreTap6 => LinkInfoData::GreTap6(payload.to_vec()),
                            LinkInfoKind::IpTun => LinkInfoData::IpTun(payload.to_vec()),
                            LinkInfoKind::SitTun => LinkInfoData::SitTun(payload.to_vec()),
                            LinkInfoKind::GreTun => LinkInfoData::GreTun(payload.to_vec()),
                            LinkInfoKind::GreTun6 => LinkInfoData::GreTun6(payload.to_vec()),
                            LinkInfoKind::Vti => LinkInfoData::Vti(payload.to_vec()),
                            LinkInfoKind::Vrf => LinkInfoData::Vrf(payload.to_vec()),
                            LinkInfoKind::Gtp => LinkInfoData::Gtp(payload.to_vec()),
                            LinkInfoKind::Other(_) => LinkInfoData::Other(payload.to_vec()),
                        };
                        res.push(LinkInfo::Data(info_data));
                    } else {
                        return Err(Error::MalformedNlaValue);
                    }
                    link_info_kind = None;
                }
                _ => return Err(Error::MalformedNlaValue),
            }
        }
        Ok(res)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkInfoData {
    Bridge(Vec<LinkInfoBridge>),
    Tun(Vec<u8>),
    Nlmon(Vec<u8>),
    Vlan(Vec<LinkInfoVlan>),
    Dummy(Vec<u8>),
    Ifb(Vec<u8>),
    Veth(LinkMessage),
    Vxlan(Vec<u8>),
    Bond(Vec<u8>),
    IpVlan(Vec<u8>),
    MacVlan(Vec<u8>),
    MacVtap(Vec<u8>),
    GreTap(Vec<u8>),
    GreTap6(Vec<u8>),
    IpTun(Vec<u8>),
    SitTun(Vec<u8>),
    GreTun(Vec<u8>),
    GreTun6(Vec<u8>),
    Vti(Vec<u8>),
    Vrf(Vec<u8>),
    Gtp(Vec<u8>),
    Other(Vec<u8>),
}

impl Nla for LinkInfoData {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::LinkInfoData::*;
        match self {
            Bridge(ref nlas) => nlas.as_slice().buffer_len(),
            Vlan(ref nlas) =>  nlas.as_slice().buffer_len(),
            Veth(ref msg) => msg.buffer_len(),
            Dummy(ref bytes)
                | Tun(ref bytes)
                | Nlmon(ref bytes)
                | Ifb(ref bytes)
                | Vxlan(ref bytes)
                | Bond(ref bytes)
                | IpVlan(ref bytes)
                | MacVlan(ref bytes)
                | MacVtap(ref bytes)
                | GreTap(ref bytes)
                | GreTap6(ref bytes)
                | IpTun(ref bytes)
                | SitTun(ref bytes)
                | GreTun(ref bytes)
                | GreTun6(ref bytes)
                | Vti(ref bytes)
                | Vrf(ref bytes)
                | Gtp(ref bytes)
                | Other(ref bytes)
                => bytes.len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkInfoData::*;
        match self {
            Bridge(ref nlas) => nlas.as_slice().emit(buffer),
            Vlan(ref nlas) => nlas.as_slice().emit(buffer),
            Veth(ref msg) => msg.emit(buffer),
            Dummy(ref bytes)
                | Tun(ref bytes)
                | Nlmon(ref bytes)
                | Ifb(ref bytes)
                | Vxlan(ref bytes)
                | Bond(ref bytes)
                | IpVlan(ref bytes)
                | MacVlan(ref bytes)
                | MacVtap(ref bytes)
                | GreTap(ref bytes)
                | GreTap6(ref bytes)
                | IpTun(ref bytes)
                | SitTun(ref bytes)
                | GreTun(ref bytes)
                | GreTun6(ref bytes)
                | Vti(ref bytes)
                | Vrf(ref bytes)
                | Gtp(ref bytes)
                | Other(ref bytes)
                => buffer.copy_from_slice(bytes),
        }
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_DATA
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkInfoKind {
    Dummy,
    Ifb,
    Bridge,
    Tun,
    Nlmon,
    Vlan,
    Veth,
    Vxlan,
    Bond,
    IpVlan,
    MacVlan,
    MacVtap,
    GreTap,
    GreTap6,
    IpTun,
    SitTun,
    GreTun,
    GreTun6,
    Vti,
    Vrf,
    Gtp,
    Other(String),
}

impl Nla for LinkInfoKind {
    fn value_len(&self) -> usize {
        use self::LinkInfoKind::*;
        let len = match *self {
            Dummy => DUMMY.len(),
            Ifb => IFB.len(),
            Bridge => BRIDGE.len(),
            Tun => TUN.len(),
            Nlmon => NLMON.len(),
            Vlan => VLAN.len(),
            Veth => VETH.len(),
            Vxlan => VXLAN.len(),
            Bond => BOND.len(),
            IpVlan => IPVLAN.len(),
            MacVlan => MACVLAN.len(),
            MacVtap => MACVTAP.len(),
            GreTap => GRETAP.len(),
            GreTap6 => IP6GRETAP.len(),
            IpTun => IPIP.len(),
            SitTun => SIT.len(),
            GreTun => GRE.len(),
            GreTun6 => IP6GRE.len(),
            Vti => VTI.len(),
            Vrf => VRF.len(),
            Gtp => GTP.len(),
            Other(ref s) => s.len(),
        };
        len + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkInfoKind::*;
        let s = match *self {
            Dummy => DUMMY,
            Ifb => IFB,
            Bridge => BRIDGE,
            Tun => TUN,
            Nlmon => NLMON,
            Vlan => VLAN,
            Veth => VETH,
            Vxlan => VXLAN,
            Bond => BOND,
            IpVlan => IPVLAN,
            MacVlan => MACVLAN,
            MacVtap => MACVTAP,
            GreTap => GRETAP,
            GreTap6 => IP6GRETAP,
            IpTun => IPIP,
            SitTun => SIT,
            GreTun => GRE,
            GreTun6 => IP6GRE,
            Vti => VTI,
            Vrf => VRF,
            Gtp => GTP,
            Other(ref s) => s.as_str(),
        };
        buffer[..s.len()].copy_from_slice(s.as_bytes());
        buffer[s.len()] = 0;
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_KIND
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkInfoKind> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<LinkInfoKind> {
        use self::LinkInfoKind::*;
        if self.kind() != IFLA_INFO_KIND {
            return Err(Error::MalformedNlaValue);
        }
        let s = parse_string(self.value())?;
        Ok(match s.as_str() {
            DUMMY => Dummy,
            IFB => Ifb,
            BRIDGE => Bridge,
            TUN => Tun,
            NLMON => Nlmon,
            VLAN => Vlan,
            VETH => Veth,
            VXLAN => Vxlan,
            BOND => Bond,
            IPVLAN => IpVlan,
            MACVLAN => MacVlan,
            MACVTAP => MacVtap,
            GRETAP => GreTap,
            IP6GRETAP => GreTap6,
            IPIP => IpTun,
            SIT => SitTun,
            GRE => GreTun,
            IP6GRE => GreTun6,
            VTI => Vti,
            VRF => Vrf,
            GTP => Gtp,
            _ => Other(s),
        })
    }
}

// https://elixir.bootlin.com/linux/latest/source/net/8021q/vlan_netlink.c#L21
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkInfoVlan {
    Unspec(Vec<u8>),
    Id(u16),
    Flags((u32, u32)),
    EgressQos(Vec<u8>),
    IngressQos(Vec<u8>),
    Protocol(u16),
}

impl Nla for LinkInfoVlan {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::LinkInfoVlan::*;
        match self {
            Id(_) | Protocol(_) => size_of::<u16>(),
            Flags(_) => size_of::<u32>() * 2,
            Unspec(bytes)
                | EgressQos(bytes)
                | IngressQos(bytes)
                => bytes.len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkInfoVlan::*;
        match self {
            Unspec(ref bytes)
                | EgressQos(ref bytes)
                | IngressQos(ref bytes)
                => buffer.copy_from_slice(bytes),

            Id(ref value)
                | Protocol(ref value)
                => NativeEndian::write_u16(buffer, *value),

            Flags(ref flags) => {
                NativeEndian::write_u32(buffer, flags.0);
                NativeEndian::write_u32(buffer, flags.1)
            }
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkInfoVlan::*;
        match self {
            Unspec(_) => IFLA_VLAN_UNSPEC,
            Id(_) => IFLA_VLAN_ID,
            Flags(_) => IFLA_VLAN_FLAGS,
            EgressQos(_) => IFLA_VLAN_EGRESS_QOS,
            IngressQos(_) => IFLA_VLAN_INGRESS_QOS,
            Protocol(_) => IFLA_VLAN_PROTOCOL,
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkInfoVlan> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<LinkInfoVlan> {
        use self::LinkInfoVlan::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFLA_VLAN_UNSPEC => Unspec(payload.to_vec()),
            IFLA_VLAN_ID => Id(parse_u16(payload)?),
            IFLA_VLAN_FLAGS => {
                let u32len = size_of::<u32>();
                if payload.len() != (u32len * 2) {
                    return Err(Error::MalformedNlaValue);
                }
                let flags = parse_u32(&payload[0..u32len])?;
                let mask = parse_u32(&payload[u32len..])?;
                Flags((flags, mask))
            }
            IFLA_VLAN_EGRESS_QOS => EgressQos(payload.to_vec()),
            IFLA_VLAN_INGRESS_QOS => IngressQos(payload.to_vec()),
            IFLA_VLAN_PROTOCOL => Protocol(parse_u16(payload)?),
            _ => return Err(Error::MalformedNlaValue),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkInfoBridge {
    Unspec(Vec<u8>),
    GroupAddr([u8; 6]),
    // FIXME: what typeh is this? putting Vec<u8> for now but it might be a boolean actually
    FdbFlush(Vec<u8>),
    Pad(Vec<u8>),
    HelloTimer(u64),
    TcnTimer(u64),
    TopologyChangeTimer(u64),
    GcTimer(u64),
    MulticastMembershipInterval(u64),
    MulticastQuerierInterval(u64),
    MulticastQueryInterval(u64),
    MulticastQueryResponseInterval(u64),
    MulticastLastMemberInterval(u64),
    MulticastStartupQueryInterval(u64),
    ForwardDelay(u32),
    HelloTime(u32),
    MaxAge(u32),
    AgeingTime(u32),
    StpState(u32),
    MulticastHashElasticity(u32),
    MulticastHashMax(u32),
    MulticastLastMemberCount(u32),
    MulticastStartupQueryCount(u32),
    RootPathCost(u32),
    Priority(u16),
    VlanProtocol(u16),
    GroupFwdMask(u16),
    RootId((u16, [u8; 6])),
    BridgeId((u16, [u8; 6])),
    RootPort(u16),
    VlanDefaultPvid(u16),
    VlanFiltering(u8),
    TopologyChange(u8),
    TopologyChangeDetected(u8),
    MulticastRouter(u8),
    MulticastSnooping(u8),
    MulticastQueryUseIfaddr(u8),
    MulticastQuerier(u8),
    NfCallIpTables(u8),
    NfCallIp6Tables(u8),
    NfCallArpTables(u8),
    VlanStatsEnabled(u8),
    MulticastStatsEnabled(u8),
    MulticastIgmpVersion(u8),
    MulticastMldVersion(u8),
    Other(DefaultNla),
}

impl Nla for LinkInfoBridge {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::LinkInfoBridge::*;
        match self {
            Unspec(bytes)
                | FdbFlush(bytes)
                | Pad(bytes)
                => bytes.len(),
            HelloTimer(_)
                | TcnTimer(_)
                | TopologyChangeTimer(_)
                | GcTimer(_)
                | MulticastMembershipInterval(_)
                | MulticastQuerierInterval(_)
                | MulticastQueryInterval(_)
                | MulticastQueryResponseInterval(_)
                | MulticastLastMemberInterval(_)
                | MulticastStartupQueryInterval(_)
                => size_of::<u64>(),
            ForwardDelay(_)
                | HelloTime(_)
                | MaxAge(_)
                | AgeingTime(_)
                | StpState(_)
                | MulticastHashElasticity(_)
                | MulticastHashMax(_)
                | MulticastLastMemberCount(_)
                | MulticastStartupQueryCount(_)
                | RootPathCost(_)
                => size_of::<u32>(),
            Priority(_)
                | VlanProtocol(_)
                | GroupFwdMask(_)
                | RootPort(_)
                | VlanDefaultPvid(_)
                => size_of::<u16>(),

            RootId(_)
                | BridgeId(_)
                => size_of::<u16>() + size_of::<[u8; 6]>(),

            GroupAddr(_) => size_of::<[u8; 6]>(),

            VlanFiltering(_)
                | TopologyChange(_)
                | TopologyChangeDetected(_)
                | MulticastRouter(_)
                | MulticastSnooping(_)
                | MulticastQueryUseIfaddr(_)
                | MulticastQuerier(_)
                | NfCallIpTables(_)
                | NfCallIp6Tables(_)
                | NfCallArpTables(_)
                | VlanStatsEnabled(_)
                | MulticastStatsEnabled(_)
                | MulticastIgmpVersion(_)
                | MulticastMldVersion(_)
                => size_of::<u8>(),
            Other(nla)
                => nla.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkInfoBridge::*;
        match self {
            Unspec(ref bytes)
                | FdbFlush(ref bytes)
                | Pad(ref bytes)
                => buffer.copy_from_slice(bytes),

            HelloTimer(ref value)
                | TcnTimer(ref value)
                | TopologyChangeTimer(ref value)
                | GcTimer(ref value)
                | MulticastMembershipInterval(ref value)
                | MulticastQuerierInterval(ref value)
                | MulticastQueryInterval(ref value)
                | MulticastQueryResponseInterval(ref value)
                | MulticastLastMemberInterval(ref value)
                | MulticastStartupQueryInterval(ref value)
                => NativeEndian::write_u64(buffer, *value),

            ForwardDelay(ref value)
                | HelloTime(ref value)
                | MaxAge(ref value)
                | AgeingTime(ref value)
                | StpState(ref value)
                | MulticastHashElasticity(ref value)
                | MulticastHashMax(ref value)
                | MulticastLastMemberCount(ref value)
                | MulticastStartupQueryCount(ref value)
                | RootPathCost(ref value)
                => NativeEndian::write_u32(buffer, *value),

            Priority(ref value)
                | VlanProtocol(ref value)
                | GroupFwdMask(ref value)
                | RootPort(ref value)
                | VlanDefaultPvid(ref value)
                => NativeEndian::write_u16(buffer, *value),

            RootId((ref priority, ref address))
                | BridgeId((ref priority, ref address))
                => {
                    NativeEndian::write_u16(buffer, *priority);
                    buffer[2..].copy_from_slice(&address[..]);
                }

            GroupAddr(ref value) => buffer.copy_from_slice(&value[..]),

            VlanFiltering(ref value)
                | TopologyChange(ref value)
                | TopologyChangeDetected(ref value)
                | MulticastRouter(ref value)
                | MulticastSnooping(ref value)
                | MulticastQueryUseIfaddr(ref value)
                | MulticastQuerier(ref value)
                | NfCallIpTables(ref value)
                | NfCallIp6Tables(ref value)
                | NfCallArpTables(ref value)
                | VlanStatsEnabled(ref value)
                | MulticastStatsEnabled(ref value)
                | MulticastIgmpVersion(ref value)
                | MulticastMldVersion(ref value)
                => buffer[0] = *value,

            Other(nla)
                => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkInfoBridge::*;
        match self {
            Unspec(_) => IFLA_BR_UNSPEC,
            GroupAddr(_) => IFLA_BR_GROUP_ADDR,
            FdbFlush(_) => IFLA_BR_FDB_FLUSH,
            Pad(_) => IFLA_BR_PAD,
            HelloTimer(_) => IFLA_BR_HELLO_TIMER,
            TcnTimer(_) => IFLA_BR_TCN_TIMER,
            TopologyChangeTimer(_) => IFLA_BR_TOPOLOGY_CHANGE_TIMER,
            GcTimer(_) => IFLA_BR_GC_TIMER,
            MulticastMembershipInterval(_) => IFLA_BR_MCAST_MEMBERSHIP_INTVL,
            MulticastQuerierInterval(_) => IFLA_BR_MCAST_QUERIER_INTVL,
            MulticastQueryInterval(_) => IFLA_BR_MCAST_QUERY_INTVL,
            MulticastQueryResponseInterval(_) => IFLA_BR_MCAST_QUERY_RESPONSE_INTVL,
            ForwardDelay(_) => IFLA_BR_FORWARD_DELAY,
            HelloTime(_) => IFLA_BR_HELLO_TIME,
            MaxAge(_) => IFLA_BR_MAX_AGE,
            AgeingTime(_) => IFLA_BR_AGEING_TIME,
            StpState(_) => IFLA_BR_STP_STATE,
            MulticastHashElasticity(_) => IFLA_BR_MCAST_HASH_ELASTICITY,
            MulticastHashMax(_) => IFLA_BR_MCAST_HASH_MAX,
            MulticastLastMemberCount(_) => IFLA_BR_MCAST_LAST_MEMBER_CNT,
            MulticastStartupQueryCount(_) => IFLA_BR_MCAST_STARTUP_QUERY_CNT,
            MulticastLastMemberInterval(_) => IFLA_BR_MCAST_LAST_MEMBER_INTVL,
            MulticastStartupQueryInterval(_) => IFLA_BR_MCAST_STARTUP_QUERY_INTVL,
            RootPathCost(_) => IFLA_BR_ROOT_PATH_COST,
            Priority(_) => IFLA_BR_PRIORITY,
            VlanProtocol(_) => IFLA_BR_VLAN_PROTOCOL,
            GroupFwdMask(_) => IFLA_BR_GROUP_FWD_MASK,
            RootId(_) => IFLA_BR_ROOT_ID,
            BridgeId(_) => IFLA_BR_BRIDGE_ID,
            RootPort(_) => IFLA_BR_ROOT_PORT,
            VlanDefaultPvid(_) => IFLA_BR_VLAN_DEFAULT_PVID,
            VlanFiltering(_) => IFLA_BR_VLAN_FILTERING,
            TopologyChange(_) => IFLA_BR_TOPOLOGY_CHANGE,
            TopologyChangeDetected(_) => IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
            MulticastRouter(_) => IFLA_BR_MCAST_ROUTER,
            MulticastSnooping(_) => IFLA_BR_MCAST_SNOOPING,
            MulticastQueryUseIfaddr(_) => IFLA_BR_MCAST_QUERY_USE_IFADDR,
            MulticastQuerier(_) => IFLA_BR_MCAST_QUERIER,
            NfCallIpTables(_) => IFLA_BR_NF_CALL_IPTABLES,
            NfCallIp6Tables(_) => IFLA_BR_NF_CALL_IP6TABLES,
            NfCallArpTables(_) => IFLA_BR_NF_CALL_ARPTABLES,
            VlanStatsEnabled(_) => IFLA_BR_VLAN_STATS_ENABLED,
            MulticastStatsEnabled(_) => IFLA_BR_MCAST_STATS_ENABLED,
            MulticastIgmpVersion(_) => IFLA_BR_MCAST_IGMP_VERSION,
            MulticastMldVersion(_) => IFLA_BR_MCAST_MLD_VERSION,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkInfoBridge> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<LinkInfoBridge> {
        use self::LinkInfoBridge::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFLA_BR_UNSPEC => Unspec(payload.to_vec()),
            IFLA_BR_FDB_FLUSH => FdbFlush(payload.to_vec()),
            IFLA_BR_PAD => Pad(payload.to_vec()),
            IFLA_BR_HELLO_TIMER => HelloTimer(parse_u64(payload)?),
            IFLA_BR_TCN_TIMER => TcnTimer(parse_u64(payload)?),
            IFLA_BR_TOPOLOGY_CHANGE_TIMER => TopologyChangeTimer(parse_u64(payload)?),
            IFLA_BR_GC_TIMER => GcTimer(parse_u64(payload)?),
            IFLA_BR_MCAST_LAST_MEMBER_INTVL => MulticastLastMemberInterval(parse_u64(payload)?),
            IFLA_BR_MCAST_MEMBERSHIP_INTVL => MulticastMembershipInterval(parse_u64(payload)?),
            IFLA_BR_MCAST_QUERIER_INTVL => MulticastQuerierInterval(parse_u64(payload)?),
            IFLA_BR_MCAST_QUERY_INTVL => MulticastQueryInterval(parse_u64(payload)?),
            IFLA_BR_MCAST_QUERY_RESPONSE_INTVL => {
                MulticastQueryResponseInterval(parse_u64(payload)?)
            }
            IFLA_BR_MCAST_STARTUP_QUERY_INTVL => MulticastStartupQueryInterval(parse_u64(payload)?),
            IFLA_BR_FORWARD_DELAY => ForwardDelay(parse_u32(payload)?),
            IFLA_BR_HELLO_TIME => HelloTime(parse_u32(payload)?),
            IFLA_BR_MAX_AGE => MaxAge(parse_u32(payload)?),
            IFLA_BR_AGEING_TIME => AgeingTime(parse_u32(payload)?),
            IFLA_BR_STP_STATE => StpState(parse_u32(payload)?),
            IFLA_BR_MCAST_HASH_ELASTICITY => MulticastHashElasticity(parse_u32(payload)?),
            IFLA_BR_MCAST_HASH_MAX => MulticastHashMax(parse_u32(payload)?),
            IFLA_BR_MCAST_LAST_MEMBER_CNT => MulticastLastMemberCount(parse_u32(payload)?),
            IFLA_BR_MCAST_STARTUP_QUERY_CNT => MulticastStartupQueryCount(parse_u32(payload)?),
            IFLA_BR_ROOT_PATH_COST => RootPathCost(parse_u32(payload)?),
            IFLA_BR_PRIORITY => Priority(parse_u16(payload)?),
            IFLA_BR_VLAN_PROTOCOL => VlanProtocol(parse_u16(payload)?),
            IFLA_BR_GROUP_FWD_MASK => GroupFwdMask(parse_u16(payload)?),
            IFLA_BR_ROOT_ID | IFLA_BR_BRIDGE_ID => {
                // XXX: we cannot do size_of::<BridgeId>() because Rust structs may contain padding
                // for better alignment.
                if payload.len() != size_of::<u16>() + size_of::<[u8; 6]>() {
                    return Err(Error::MalformedNlaValue);
                }

                let priority = NativeEndian::read_u16(&payload[..2]);
                let address = parse_mac(&payload[2..])?;

                match self.kind() {
                    IFLA_BR_ROOT_ID => RootId((priority, address)),
                    IFLA_BR_BRIDGE_ID => BridgeId((priority, address)),
                    _ => unreachable!(),
                }
            }
            IFLA_BR_GROUP_ADDR => GroupAddr(parse_mac(payload)?),
            IFLA_BR_ROOT_PORT => RootPort(parse_u16(payload)?),
            IFLA_BR_VLAN_DEFAULT_PVID => VlanDefaultPvid(parse_u16(payload)?),
            IFLA_BR_VLAN_FILTERING => VlanFiltering(parse_u8(payload)?),
            IFLA_BR_TOPOLOGY_CHANGE => TopologyChange(parse_u8(payload)?),
            IFLA_BR_TOPOLOGY_CHANGE_DETECTED => TopologyChangeDetected(parse_u8(payload)?),
            IFLA_BR_MCAST_ROUTER => MulticastRouter(parse_u8(payload)?),
            IFLA_BR_MCAST_SNOOPING => MulticastSnooping(parse_u8(payload)?),
            IFLA_BR_MCAST_QUERY_USE_IFADDR => MulticastQueryUseIfaddr(parse_u8(payload)?),
            IFLA_BR_MCAST_QUERIER => MulticastQuerier(parse_u8(payload)?),
            IFLA_BR_NF_CALL_IPTABLES => NfCallIpTables(parse_u8(payload)?),
            IFLA_BR_NF_CALL_IP6TABLES => NfCallIp6Tables(parse_u8(payload)?),
            IFLA_BR_NF_CALL_ARPTABLES => NfCallArpTables(parse_u8(payload)?),
            IFLA_BR_VLAN_STATS_ENABLED => VlanStatsEnabled(parse_u8(payload)?),
            IFLA_BR_MCAST_STATS_ENABLED => MulticastStatsEnabled(parse_u8(payload)?),
            IFLA_BR_MCAST_IGMP_VERSION => MulticastIgmpVersion(parse_u8(payload)?),
            IFLA_BR_MCAST_MLD_VERSION => MulticastMldVersion(parse_u8(payload)?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(nightly, rustfmt::skip)]
    static BRIDGE: [u8; 404] = [
        0x0b, 0x00, // L = 11
        0x01, 0x00, // T = 1 (IFLA_INFO_KIND)
        0x62, 0x72, 0x69, 0x64, 0x67, 0x65, 0x00, // V = "bridge"
        0x00, // padding

        0x88, 0x01, // L = 392
        0x02, 0x00, // T = 2 (IFLA_INFO_DATA)

            0x0c, 0x00, // L = 12
            0x10, 0x00, // T = 16 (IFLA_BR_HELLO_TIMER)
            0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 35

            0x0c, 0x00, // L = 12
            0x11, 0x00, // T = 17 (IFLA_BR_TCN_TIMER)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 0

            0x0c, 0x00, // L = 12
            0x12, 0x00, // T = 18 (IFLA_BR_TOPOLOGY_CHANGE_TIMER)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 0

            0x0c, 0x00, //  L = 12
            0x13, 0x00, // T = 19 (IFLA_BR_GC_TIMER)
            0xb5, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 14261 (0x37b5)

            0x08, 0x00, // L = 8
            0x01, 0x00, // T = 1 (IFLA_BR_FORWARD_DELAY)
            0xc7, 0x00, 0x00, 0x00, // V = 199

            0x08, 0x00, // L = 8
            0x02, 0x00, // T = 2 (IFLA_BR_HELLO_TIME)
            0xc7, 0x00, 0x00, 0x00, // V = 199

            0x08, 0x00, // L = 8
            0x03, 0x00, // T = 3 (IFLA_BR_MAX_AGE)
            0xcf, 0x07, 0x00, 0x00, // V = 1999 (0x07cf)

            0x08, 0x00, // L = 8
            0x04, 0x00, // T = 4 (IFLA_BR_AGEING_TIME)
            0x2f, 0x75, 0x00, 0x00, // V = 29999 (0x752f)

            0x08, 0x00, // L = 8
            0x05, 0x00, // T = 5 (IFLA_BR_STP_STATE)
            0x01, 0x00, 0x00, 0x00, // V = 1

            0x06, 0x00, // L = 6
            0x06, 0x00, // T = 6 (IFLA_BR_PRIORITY)
            0x00, 0x80, // V =  32768 (0x8000)
            0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x07, 0x00, // T = 7 (IFLA_BR_VLAN_FILTERING)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x06, 0x00, // L = 6
            0x09, 0x00, // T = 9 (IFLA_BR_GROUP_FWD_MASK)
            0x00, 0x00, // V = 0
            0x00, 0x00, // Padding

            0x0c, 0x00, // L = 12
            0x0b, 0x00, // T = 11 (IFLA_BR_BRIDGE_ID)
            0x80, 0x00, // V (priority) = 128 (0x80)
            0x52, 0x54, 0x00, 0xd7, 0x19, 0x3e, // V (address) = 52:54:00:d7:19:3e

            0x0c, 0x00, // L = 12
            0x0a, 0x00, // T = 10 (IFLA_BR_ROOT_ID)
            0x80, 0x00, // V (priority) = 128 (0x80)
            0x52, 0x54, 0x00, 0xd7, 0x19, 0x3e, // V (address) = 52:54:00:d7:19:3e

            0x06, 0x00, // L = 6
            0x0c, 0x00, // T = 12 (IFLA_BR_ROOT_PORT)
            0x00, 0x00, // V = 0
            0x00, 0x00, // Padding

            0x08, 0x00, // L = 8
            0x0d, 0x00, // T = 13 (IFLA_BR_ROOT_PATH_COST)
            0x00, 0x00, 0x00, 0x00, // V = 0

            0x05, 0x00, // L = 5
            0x0e, 0x00, // T = 14 (IFLA_BR_TOPOLOGY_CHANGE)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x0f, 0x00, // T = 15 (IFLA_BR_TOPOLOGY_CHANGE_DETECTED)
            0x00, // V = 0 
            0x00, 0x00, 0x00, // Padding

            0x0a, 0x00, // L = 10
            0x14, 0x00, // T = 20 (IFLA_BR_GROUP_ADDR)
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, // V = 01:80:c2:00:00:00
            0x00, 0x00, // Padding

            0x06, 0x00, // L = 6
            0x08, 0x00, // T = 8 (IFLA_BR_VLAN_PROTOCOL)
            0x81, 0x00, // V = 129
            0x00, 0x00, // Padding

            0x06, 0x00, // L = 6
            0x27, 0x00, // T = 39 (IFLA_BR_VLAN_DEFAULT_PVID)
            0x01, 0x00, // V = 1
            0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x29, 0x00, // T = 41 (IFLA_BR_VLAN_STATS_ENABLED)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x16, 0x00, // T = 22 (IFLA_BR_MCAST_ROUTER)
            0x01, // V = 1
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x17, 0x00, // T = 23 (IFLA_BR_MCAST_SNOOPING)
            0x01, // V = 1
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x18, 0x00, // T = 24 (IFLA_BR_MCAST_QUERY_USE_IFADDR)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x19, 0x00, // T = 25 (IFLA_BR_MCAST_QUERIER)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x2a, 0x00, // T = 42 (IFLA_BR_MCAST_STATS_ENABLED)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x08, 0x00, // L = 8
            0x1a, 0x00, // T = 26 (IFLA_BR_MCAST_HASH_ELASTICITY)
            0x04, 0x00, 0x00, 0x00, // V = 4

            0x08, 0x00, // L = 8
            0x1b, 0x00, // T = 27 (IFLA_BR_MCAST_HASH_MAX)
            0x00, 0x02, 0x00, 0x00, // V = 512 (0x0200)

            0x08, 0x00, // L = 8
            0x1c, 0x00, // T = 28 (IFLA_BR_MCAST_LAST_MEMBER_CNT)
            0x02, 0x00, 0x00, 0x00, // V = 2

            0x08, 0x00, // L = 8
            0x1d, 0x00, // T = 29 (IFLA_BR_MCAST_STARTUP_QUERY_CNT)
            0x02, 0x00, 0x00, 0x00, // V = 2

            0x05, 0x00, // L = 5
            0x2b, 0x00, // T = 43 (IFLA_BR_MCAST_IGMP_VERSION)
            0x02, // V = 2
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x2c, 0x00, // T = 44 (IFLA_BR_MCAST_MLD_VERSION)
            0x01, // V = 1
            0x00, 0x00, 0x00, // Padding

            0x0c, 0x00, // L = 12
            0x1e, 0x00, // T = 30 (IFLA_BR_MCAST_LAST_MEMBER_INTVL)
            0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 99

            0x0c, 0x00, // L = 12
            0x1f, 0x00, // T = 31 (IFLA_BR_MCAST_MEMBERSHIP_INTVL)
            0x8f, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 25999 (0x658f)

            0x0c, 0x00, // L = 12
            0x20, 0x00, // T = 32 (IFLA_BR_MCAST_QUERIER_INTVL)
            0x9b, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 25499 (0x639b)

            0x0c, 0x00, // L = 12
            0x21, 0x00, // T = 33 (IFLA_BR_MCAST_QUERY_INTVL)
            0xd3, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 12499 (0x30d3)

            0x0c, 0x00, // L = 12
            0x22, 0x00, // T = 34 (IFLA_BR_MCAST_QUERY_RESPONSE_INTVL)
            0xe7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 999 (0x03e7)

            0x0c, 0x00, // L = 12
            0x23, 0x00, // T = 35 (IFLA_BR_MCAST_STARTUP_QUERY_INTVL)
            0x34, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // V = 3124 (0x0c34)

            0x05, 0x00, // L = 5
            0x24, 0x00, // T = 36 (IFLA_BR_NF_CALL_IPTABLES)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x25, 0x00, // T = 37 (IFLA_BR_NF_CALL_IP6TABLES)
            0x00, // V = 0
            0x00, 0x00, 0x00, // Padding

            0x05, 0x00, // L = 5
            0x26, 0x00, // T = 38 (IFLA_BR_NF_CALL_ARPTABLES)
            0x00, // V = 0
            0x00, 0x00, 0x00 // Padding
    ];

    lazy_static! {
        static ref BRIDGE_INFO: Vec<LinkInfoBridge> = vec![
            LinkInfoBridge::HelloTimer(35),
            LinkInfoBridge::TcnTimer(0),
            LinkInfoBridge::TopologyChangeTimer(0),
            LinkInfoBridge::GcTimer(14261),
            LinkInfoBridge::ForwardDelay(199),
            LinkInfoBridge::HelloTime(199),
            LinkInfoBridge::MaxAge(1999),
            LinkInfoBridge::AgeingTime(29999),
            LinkInfoBridge::StpState(1),
            LinkInfoBridge::Priority(0x8000),
            LinkInfoBridge::VlanFiltering(0),
            LinkInfoBridge::GroupFwdMask(0),
            LinkInfoBridge::BridgeId((128, [0x52, 0x54, 0x00, 0xd7, 0x19, 0x3e])),
            LinkInfoBridge::RootId((128, [0x52, 0x54, 0x00, 0xd7, 0x19, 0x3e])),
            LinkInfoBridge::RootPort(0),
            LinkInfoBridge::RootPathCost(0),
            LinkInfoBridge::TopologyChange(0),
            LinkInfoBridge::TopologyChangeDetected(0),
            LinkInfoBridge::GroupAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]),
            LinkInfoBridge::VlanProtocol(129),
            LinkInfoBridge::VlanDefaultPvid(1),
            LinkInfoBridge::VlanStatsEnabled(0),
            LinkInfoBridge::MulticastRouter(1),
            LinkInfoBridge::MulticastSnooping(1),
            LinkInfoBridge::MulticastQueryUseIfaddr(0),
            LinkInfoBridge::MulticastQuerier(0),
            LinkInfoBridge::MulticastStatsEnabled(0),
            LinkInfoBridge::MulticastHashElasticity(4),
            LinkInfoBridge::MulticastHashMax(512),
            LinkInfoBridge::MulticastLastMemberCount(2),
            LinkInfoBridge::MulticastStartupQueryCount(2),
            LinkInfoBridge::MulticastIgmpVersion(2),
            LinkInfoBridge::MulticastMldVersion(1),
            LinkInfoBridge::MulticastLastMemberInterval(99),
            LinkInfoBridge::MulticastMembershipInterval(25999),
            LinkInfoBridge::MulticastQuerierInterval(25499),
            LinkInfoBridge::MulticastQueryInterval(12499),
            LinkInfoBridge::MulticastQueryResponseInterval(999),
            LinkInfoBridge::MulticastStartupQueryInterval(3124),
            LinkInfoBridge::NfCallIpTables(0),
            LinkInfoBridge::NfCallIp6Tables(0),
            LinkInfoBridge::NfCallArpTables(0),
        ];
    }

    #[test]
    fn parse_info_kind() {
        let info_kind_nla = NlaBuffer::new_checked(&BRIDGE[..12]).unwrap();
        let parsed = <NlaBuffer<_> as Parseable<LinkInfoKind>>::parse(&info_kind_nla).unwrap();
        assert_eq!(parsed, LinkInfoKind::Bridge);
    }

    #[test]
    fn parse_info_bridge() {
        let nlas = NlasIterator::new(&BRIDGE[16..]);
        for nla in nlas.map(|nla| nla.unwrap()) {
            <NlaBuffer<_> as Parseable<LinkInfoBridge>>::parse(&nla).unwrap();
        }
    }

    #[test]
    fn parse() {
        let nla = NlaBuffer::new_checked(&BRIDGE[..]).unwrap();
        let parsed = <NlaBuffer<_> as Parseable<Vec<LinkInfo>>>::parse(&nla).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], LinkInfo::Kind(LinkInfoKind::Bridge));
        if let LinkInfo::Data(LinkInfoData::Bridge(nlas)) = parsed[1].clone() {
            assert_eq!(nlas.len(), BRIDGE_INFO.len());
            for (expected, parsed) in BRIDGE_INFO.iter().zip(nlas) {
                assert_eq!(*expected, parsed);
            }
        } else {
            panic!(
                "expected  LinkInfo::Data(LinkInfoData::Bridge(_) got {:?}",
                parsed[1]
            )
        }
    }

    #[test]
    fn emit() {
        let nlas = vec![
            LinkInfo::Kind(LinkInfoKind::Bridge),
            LinkInfo::Data(LinkInfoData::Bridge(BRIDGE_INFO.clone())),
        ];

        assert_eq!(nlas.as_slice().buffer_len(), 404);

        let mut vec = vec![0xff; 404];
        nlas.as_slice().emit(&mut vec);
        assert_eq!(&vec[..], &BRIDGE[..]);
    }
}
