// SPDX-License-Identifier: MIT

use crate::{
    constants::*,
    nlas::{DefaultNla, Nla, NlaBuffer, NlasIterator, NLA_F_NESTED},
    parsers::{parse_ip, parse_mac, parse_u16, parse_u16_be, parse_u32, parse_u64, parse_u8},
    traits::{Emitable, Parseable},
    DecodeError,
};

use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, NativeEndian};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const BRIDGE_QUERIER_IP_ADDRESS: u16 = 1;
const BRIDGE_QUERIER_IP_PORT: u16 = 2;
const BRIDGE_QUERIER_IP_OTHER_TIMER: u16 = 3;
// const BRIDGE_QUERIER_PAD: u16 = 4;
const BRIDGE_QUERIER_IPV6_ADDRESS: u16 = 5;
const BRIDGE_QUERIER_IPV6_PORT: u16 = 6;
const BRIDGE_QUERIER_IPV6_OTHER_TIMER: u16 = 7;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InfoBridge {
    Unspec(Vec<u8>),
    GroupAddr([u8; 6]),
    // FIXME: what type is this? putting Vec<u8> for now but it might
    // be a boolean actually
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
    VlanStatsPerHost(u8),
    MultiBoolOpt(u64),
    MulticastQuerierState(Vec<BridgeQuerierState>),
    Other(DefaultNla),
}

impl Nla for InfoBridge {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::InfoBridge::*;
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
                => 8,
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
                => 4,
            Priority(_)
                | VlanProtocol(_)
                | GroupFwdMask(_)
                | RootPort(_)
                | VlanDefaultPvid(_)
                => 2,

            RootId(_)
                | BridgeId(_)
                | MultiBoolOpt(_)
                => 8,

            GroupAddr(_) => 6,

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
                | VlanStatsPerHost(_)
                => 1,

            MulticastQuerierState(ref nlas) => nlas.as_slice().buffer_len(),

            Other(nla)
                => nla.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoBridge::*;
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
                | MultiBoolOpt(ref value)
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
                | GroupFwdMask(ref value)
                | RootPort(ref value)
                | VlanDefaultPvid(ref value)
                => NativeEndian::write_u16(buffer, *value),

            VlanProtocol(ref value)
                => BigEndian::write_u16(buffer, *value),

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
                | VlanStatsPerHost(ref value)
                => buffer[0] = *value,

            MulticastQuerierState(ref nlas) => nlas.as_slice().emit(buffer),

            Other(nla)
                => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoBridge::*;
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
            VlanStatsPerHost(_) => IFLA_BR_VLAN_STATS_PER_PORT,
            MultiBoolOpt(_) => IFLA_BR_MULTI_BOOLOPT,
            MulticastQuerierState(_) => IFLA_BR_MCAST_QUERIER_STATE | NLA_F_NESTED,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoBridge {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoBridge::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BR_UNSPEC => Unspec(payload.to_vec()),
            IFLA_BR_FDB_FLUSH => FdbFlush(payload.to_vec()),
            IFLA_BR_PAD => Pad(payload.to_vec()),
            IFLA_BR_HELLO_TIMER => {
                HelloTimer(parse_u64(payload).context("invalid IFLA_BR_HELLO_TIMER value")?)
            }
            IFLA_BR_TCN_TIMER => {
                TcnTimer(parse_u64(payload).context("invalid IFLA_BR_TCN_TIMER value")?)
            }
            IFLA_BR_TOPOLOGY_CHANGE_TIMER => TopologyChangeTimer(
                parse_u64(payload).context("invalid IFLA_BR_TOPOLOGY_CHANGE_TIMER value")?,
            ),
            IFLA_BR_GC_TIMER => {
                GcTimer(parse_u64(payload).context("invalid IFLA_BR_GC_TIMER value")?)
            }
            IFLA_BR_MCAST_LAST_MEMBER_INTVL => MulticastLastMemberInterval(
                parse_u64(payload).context("invalid IFLA_BR_MCAST_LAST_MEMBER_INTVL value")?,
            ),
            IFLA_BR_MCAST_MEMBERSHIP_INTVL => MulticastMembershipInterval(
                parse_u64(payload).context("invalid IFLA_BR_MCAST_MEMBERSHIP_INTVL value")?,
            ),
            IFLA_BR_MCAST_QUERIER_INTVL => MulticastQuerierInterval(
                parse_u64(payload).context("invalid IFLA_BR_MCAST_QUERIER_INTVL value")?,
            ),
            IFLA_BR_MCAST_QUERY_INTVL => MulticastQueryInterval(
                parse_u64(payload).context("invalid IFLA_BR_MCAST_QUERY_INTVL value")?,
            ),
            IFLA_BR_MCAST_QUERY_RESPONSE_INTVL => MulticastQueryResponseInterval(
                parse_u64(payload).context("invalid IFLA_BR_MCAST_QUERY_RESPONSE_INTVL value")?,
            ),
            IFLA_BR_MCAST_STARTUP_QUERY_INTVL => MulticastStartupQueryInterval(
                parse_u64(payload).context("invalid IFLA_BR_MCAST_STARTUP_QUERY_INTVL value")?,
            ),
            IFLA_BR_FORWARD_DELAY => {
                ForwardDelay(parse_u32(payload).context("invalid IFLA_BR_FORWARD_DELAY value")?)
            }
            IFLA_BR_HELLO_TIME => {
                HelloTime(parse_u32(payload).context("invalid IFLA_BR_HELLO_TIME value")?)
            }
            IFLA_BR_MAX_AGE => MaxAge(parse_u32(payload).context("invalid IFLA_BR_MAX_AGE value")?),
            IFLA_BR_AGEING_TIME => {
                AgeingTime(parse_u32(payload).context("invalid IFLA_BR_AGEING_TIME value")?)
            }
            IFLA_BR_STP_STATE => {
                StpState(parse_u32(payload).context("invalid IFLA_BR_STP_STATE value")?)
            }
            IFLA_BR_MCAST_HASH_ELASTICITY => MulticastHashElasticity(
                parse_u32(payload).context("invalid IFLA_BR_MCAST_HASH_ELASTICITY value")?,
            ),
            IFLA_BR_MCAST_HASH_MAX => MulticastHashMax(
                parse_u32(payload).context("invalid IFLA_BR_MCAST_HASH_MAX value")?,
            ),
            IFLA_BR_MCAST_LAST_MEMBER_CNT => MulticastLastMemberCount(
                parse_u32(payload).context("invalid IFLA_BR_MCAST_LAST_MEMBER_CNT value")?,
            ),
            IFLA_BR_MCAST_STARTUP_QUERY_CNT => MulticastStartupQueryCount(
                parse_u32(payload).context("invalid IFLA_BR_MCAST_STARTUP_QUERY_CNT value")?,
            ),
            IFLA_BR_ROOT_PATH_COST => {
                RootPathCost(parse_u32(payload).context("invalid IFLA_BR_ROOT_PATH_COST value")?)
            }
            IFLA_BR_PRIORITY => {
                Priority(parse_u16(payload).context("invalid IFLA_BR_PRIORITY value")?)
            }
            IFLA_BR_VLAN_PROTOCOL => {
                VlanProtocol(parse_u16_be(payload).context("invalid IFLA_BR_VLAN_PROTOCOL value")?)
            }
            IFLA_BR_GROUP_FWD_MASK => {
                GroupFwdMask(parse_u16(payload).context("invalid IFLA_BR_GROUP_FWD_MASK value")?)
            }
            IFLA_BR_ROOT_ID | IFLA_BR_BRIDGE_ID => {
                if payload.len() != 8 {
                    return Err("invalid IFLA_BR_ROOT_ID or IFLA_BR_BRIDGE_ID value".into());
                }

                let priority = NativeEndian::read_u16(&payload[..2]);
                let address = parse_mac(&payload[2..])
                    .context("invalid IFLA_BR_ROOT_ID or IFLA_BR_BRIDGE_ID value")?;

                match buf.kind() {
                    IFLA_BR_ROOT_ID => RootId((priority, address)),
                    IFLA_BR_BRIDGE_ID => BridgeId((priority, address)),
                    _ => unreachable!(),
                }
            }
            IFLA_BR_GROUP_ADDR => {
                GroupAddr(parse_mac(payload).context("invalid IFLA_BR_GROUP_ADDR value")?)
            }
            IFLA_BR_ROOT_PORT => {
                RootPort(parse_u16(payload).context("invalid IFLA_BR_ROOT_PORT value")?)
            }
            IFLA_BR_VLAN_DEFAULT_PVID => VlanDefaultPvid(
                parse_u16(payload).context("invalid IFLA_BR_VLAN_DEFAULT_PVID value")?,
            ),
            IFLA_BR_VLAN_FILTERING => {
                VlanFiltering(parse_u8(payload).context("invalid IFLA_BR_VLAN_FILTERING value")?)
            }
            IFLA_BR_TOPOLOGY_CHANGE => {
                TopologyChange(parse_u8(payload).context("invalid IFLA_BR_TOPOLOGY_CHANGE value")?)
            }
            IFLA_BR_TOPOLOGY_CHANGE_DETECTED => TopologyChangeDetected(
                parse_u8(payload).context("invalid IFLA_BR_TOPOLOGY_CHANGE_DETECTED value")?,
            ),
            IFLA_BR_MCAST_ROUTER => {
                MulticastRouter(parse_u8(payload).context("invalid IFLA_BR_MCAST_ROUTER value")?)
            }
            IFLA_BR_MCAST_SNOOPING => MulticastSnooping(
                parse_u8(payload).context("invalid IFLA_BR_MCAST_SNOOPING value")?,
            ),
            IFLA_BR_MCAST_QUERY_USE_IFADDR => MulticastQueryUseIfaddr(
                parse_u8(payload).context("invalid IFLA_BR_MCAST_QUERY_USE_IFADDR value")?,
            ),
            IFLA_BR_MCAST_QUERIER => {
                MulticastQuerier(parse_u8(payload).context("invalid IFLA_BR_MCAST_QUERIER value")?)
            }
            IFLA_BR_NF_CALL_IPTABLES => {
                NfCallIpTables(parse_u8(payload).context("invalid IFLA_BR_NF_CALL_IPTABLES value")?)
            }
            IFLA_BR_NF_CALL_IP6TABLES => NfCallIp6Tables(
                parse_u8(payload).context("invalid IFLA_BR_NF_CALL_IP6TABLES value")?,
            ),
            IFLA_BR_NF_CALL_ARPTABLES => NfCallArpTables(
                parse_u8(payload).context("invalid IFLA_BR_NF_CALL_ARPTABLES value")?,
            ),
            IFLA_BR_VLAN_STATS_ENABLED => VlanStatsEnabled(
                parse_u8(payload).context("invalid IFLA_BR_VLAN_STATS_ENABLED value")?,
            ),
            IFLA_BR_MCAST_STATS_ENABLED => MulticastStatsEnabled(
                parse_u8(payload).context("invalid IFLA_BR_MCAST_STATS_ENABLED value")?,
            ),
            IFLA_BR_MCAST_IGMP_VERSION => MulticastIgmpVersion(
                parse_u8(payload).context("invalid IFLA_BR_MCAST_IGMP_VERSION value")?,
            ),
            IFLA_BR_MCAST_MLD_VERSION => MulticastMldVersion(
                parse_u8(payload).context("invalid IFLA_BR_MCAST_MLD_VERSION value")?,
            ),
            IFLA_BR_VLAN_STATS_PER_PORT => VlanStatsPerHost(
                parse_u8(payload).context("invalid IFLA_BR_VLAN_STATS_PER_PORT value")?,
            ),
            IFLA_BR_MULTI_BOOLOPT => {
                MultiBoolOpt(parse_u64(payload).context("invalid IFLA_BR_MULTI_BOOLOPT value")?)
            }
            IFLA_BR_MCAST_QUERIER_STATE => {
                let mut v = Vec::new();
                let err = "failed to parse IFLA_BR_MCAST_QUERIER_STATE";
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err)?;
                    let parsed = BridgeQuerierState::parse(nla).context(err)?;
                    v.push(parsed);
                }
                MulticastQuerierState(v)
            }
            _ => Other(
                DefaultNla::parse(buf)
                    .context("invalid link info bridge NLA value (unknown type)")?,
            ),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BridgeQuerierState {
    Ipv4Address(Ipv4Addr),
    Ipv4Port(u32),
    Ipv4OtherTimer(u64),
    Ipv6Address(Ipv6Addr),
    Ipv6Port(u32),
    Ipv6OtherTimer(u64),
    Other(DefaultNla),
}

impl Nla for BridgeQuerierState {
    fn value_len(&self) -> usize {
        use self::BridgeQuerierState::*;
        match self {
            Ipv4Address(_) => 4,
            Ipv6Address(_) => 16,
            Ipv4Port(_) | Ipv6Port(_) => 4,
            Ipv4OtherTimer(_) | Ipv6OtherTimer(_) => 8,
            Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use self::BridgeQuerierState::*;
        match self {
            Ipv4Address(_) => BRIDGE_QUERIER_IP_ADDRESS,
            Ipv4Port(_) => BRIDGE_QUERIER_IP_PORT,
            Ipv4OtherTimer(_) => BRIDGE_QUERIER_IP_OTHER_TIMER,
            Ipv6Address(_) => BRIDGE_QUERIER_IPV6_ADDRESS,
            Ipv6Port(_) => BRIDGE_QUERIER_IPV6_PORT,
            Ipv6OtherTimer(_) => BRIDGE_QUERIER_IPV6_OTHER_TIMER,
            Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::BridgeQuerierState::*;
        match self {
            Ipv4Port(d) | Ipv6Port(d) => NativeEndian::write_u32(buffer, *d),
            Ipv4OtherTimer(d) | Ipv6OtherTimer(d) => NativeEndian::write_u64(buffer, *d),
            Ipv4Address(addr) => buffer.copy_from_slice(&addr.octets()),
            Ipv6Address(addr) => buffer.copy_from_slice(&addr.octets()),
            Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for BridgeQuerierState {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::BridgeQuerierState::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            BRIDGE_QUERIER_IP_ADDRESS => match parse_ip(payload) {
                Ok(IpAddr::V4(addr)) => Ipv4Address(addr),
                Ok(v) => {
                    return Err(DecodeError::from(format!(
                        "Invalid BRIDGE_QUERIER_IP_ADDRESS, \
                        expecting IPv4 address, but got {}",
                        v
                    )))
                }
                Err(e) => {
                    return Err(DecodeError::from(format!(
                        "Invalid BRIDGE_QUERIER_IP_ADDRESS {}",
                        e
                    )))
                }
            },
            BRIDGE_QUERIER_IPV6_ADDRESS => match parse_ip(payload) {
                Ok(IpAddr::V6(addr)) => Ipv6Address(addr),
                Ok(v) => {
                    return Err(DecodeError::from(format!(
                        "Invalid BRIDGE_QUERIER_IPV6_ADDRESS, \
                        expecting IPv6 address, but got {}",
                        v
                    )));
                }
                Err(e) => {
                    return Err(DecodeError::from(format!(
                        "Invalid BRIDGE_QUERIER_IPV6_ADDRESS {}",
                        e
                    )));
                }
            },
            BRIDGE_QUERIER_IP_PORT => {
                Ipv4Port(parse_u32(payload).context("invalid BRIDGE_QUERIER_IP_PORT value")?)
            }
            BRIDGE_QUERIER_IPV6_PORT => {
                Ipv6Port(parse_u32(payload).context("invalid BRIDGE_QUERIER_IPV6_PORT value")?)
            }
            BRIDGE_QUERIER_IP_OTHER_TIMER => Ipv4OtherTimer(
                parse_u64(payload).context("invalid BRIDGE_QUERIER_IP_OTHER_TIMER value")?,
            ),
            BRIDGE_QUERIER_IPV6_OTHER_TIMER => Ipv6OtherTimer(
                parse_u64(payload).context("invalid BRIDGE_QUERIER_IPV6_OTHER_TIMER value")?,
            ),

            kind => Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        nlas::NlaBuffer,
        utils::{Emitable, Parseable},
    };

    use super::{BridgeQuerierState, InfoBridge};

    #[rustfmt::skip]
    // This is capture of nlmon of `ip -d link show br0` after:
    //      ip link set br0 type bridge mcast_snooping 1
    //      ip link set br0 type bridge mcast_querier 1
    //      ip link set br0 type bridge mcast_stats_enabled 1
    const BR_MCAST_QUERIER_STATE_DUMP: [u8; 32] = [
        0x20, 0x00,                     // len: 32
        0x2f, 0x80,                     // IFLA_BR_MCAST_QUERIER_STATE | NLA_F_NESTED
        0x08, 0x00,                     // len: 8
        0x01, 0x00,                     // BRIDGE_QUERIER_IP_ADDRESS
        0x00, 0x00, 0x00, 0x00,         // 0.0.0.0
        0x14, 0x00,                     // len: 20
        0x05, 0x00,                     // BRIDGE_QUERIER_IPV6_ADDRESS
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x23, 0x45, 0xff, 0xfe, 0x67, 0x89, 0x1c, // fe80::223:45ff:fe67:891c
    ];

    #[test]
    fn test_br_multicast_querier_state_parse() {
        let expected = vec![
            BridgeQuerierState::Ipv4Address("0.0.0.0".parse().unwrap()),
            BridgeQuerierState::Ipv6Address("fe80::223:45ff:fe67:891c".parse().unwrap()),
        ];
        let nla = NlaBuffer::new_checked(&BR_MCAST_QUERIER_STATE_DUMP[..]).unwrap();
        let parsed = if let InfoBridge::MulticastQuerierState(s) = InfoBridge::parse(&nla).unwrap()
        {
            s
        } else {
            panic!("Failed for parse IFLA_BR_MCAST_QUERIER_STATE")
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_br_multicast_querier_state_emit() {
        let mut expected = [0u8; 32];
        InfoBridge::MulticastQuerierState(vec![
            BridgeQuerierState::Ipv4Address("0.0.0.0".parse().unwrap()),
            BridgeQuerierState::Ipv6Address("fe80::223:45ff:fe67:891c".parse().unwrap()),
        ])
        .emit(&mut expected);

        assert_eq!(expected, BR_MCAST_QUERIER_STATE_DUMP);
    }
}
