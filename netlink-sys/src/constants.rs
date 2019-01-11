#![allow(unused)]

use libc;
use libc::c_int as int;

/// The message is ignored.
pub const NLMSG_NOOP: u16 = 1;
/// The message signals an error and the payload contains a nlmsgerr structure. This can be looked
/// at as a NACK and typically it is from FEC to CPC.
pub const NLMSG_ERROR: u16 = 2;
/// The message terminates a multipart message.
/// Data lost
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;
pub const NLMSG_ALIGNTO: u16 = 4;

/// Receives routing and link updates and may be used to modify the routing tables (both IPv4
/// and IPv6), IP addresses, link parameters, neighbor setups, queueing disciplines, traffic
/// classes  and  packet  classifiers  (see rtnetlink(7)).
pub const NETLINK_ROUTE: isize = 0;
pub const NETLINK_UNUSED: isize = 1;
/// Reserved for user-mode socket protocols.
pub const NETLINK_USERSOCK: isize = 2;
/// Transport  IPv4  packets  from  netfilter  to  user  space.  Used by ip_queue kernel
/// module.  After a long period of being declared obsolete (in favor of the more advanced
/// nfnetlink_queue feature), it was  removed in Linux 3.5.
pub const NETLINK_FIREWALL: isize = 3;
/// Query information about sockets of various protocol families from the kernel (see sock_diag(7)).
pub const NETLINK_SOCK_DIAG: isize = 4;
/// Netfilter/iptables ULOG.
pub const NETLINK_NFLOG: isize = 5;
/// IPsec.
pub const NETLINK_XFRM: isize = 6;
/// SELinux event notifications.
pub const NETLINK_SELINUX: isize = 7;
/// Open-iSCSI.
pub const NETLINK_ISCSI: isize = 8;
/// Auditing.
pub const NETLINK_AUDIT: isize = 9;
/// Access to FIB lookup from user space.
pub const NETLINK_FIB_LOOKUP: isize = 10;
/// Kernel connector. See `Documentation/connector/*` in the Linux kernel source tree for further information.
pub const NETLINK_CONNECTOR: isize = 11;
/// Netfilter subsystem.
pub const NETLINK_NETFILTER: isize = 12;
/// Transport IPv6 packets from netfilter to user space.  Used by ip6_queue kernel module.
pub const NETLINK_IP6_FW: isize = 13;
/// DECnet routing messages.
pub const NETLINK_DNRTMSG: isize = 14;
/// Kernel messages to user space.
pub const NETLINK_KOBJECT_UEVENT: isize = 15;
///  Generic netlink family for simplified netlink usage.
pub const NETLINK_GENERIC: isize = 16;
/// SCSI transpots
pub const NETLINK_SCSITRANSPORT: isize = 18;
///
pub const NETLINK_ECRYPTFS: isize = 19;
/// Infiniband RDMA.
pub const NETLINK_RDMA: isize = 20;
/// Netlink interface to request information about ciphers registered with the kernel crypto
/// API as well as allow configuration of the kernel crypto API.
pub const NETLINK_CRYPTO: isize = 21;

/// Identify the bits that represent the "nested" flag of a netlink attribute.
pub const NLA_F_NESTED: u16 = 0x8000;
/// Identify the bits that represent the "byte order" flag of a netlink attribute.
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
/// Identify the bits that represent the type of a netlink attribute.
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NET_BYTEORDER | NLA_F_NESTED);

pub const NLA_ALIGNTO: u16 = 4;

/// Must be set on all request messages (typically from user space to kernel space)
pub const NLM_F_REQUEST: u16 = 1;
///  Indicates the message is part of a multipart message terminated by NLMSG_DONE
pub const NLM_F_MULTIPART: u16 = 2;
/// Request for an acknowledgment on success. Typical direction of request is from user space
/// (CPC) to kernel space (FEC).
pub const NLM_F_ACK: u16 = 4;
/// Echo this request.  Typical direction of request is from user space (CPC) to kernel space
/// (FEC).
pub const NLM_F_ECHO: u16 = 8;
/// Dump was inconsistent due to sequence change
pub const NLM_F_DUMP_INTR: u16 = 16;
/// Dump was filtered as requested
pub const NLM_F_DUMP_FILTERED: u16 = 32;
/// Return the complete table instead of a single entry.
pub const NLM_F_ROOT: u16 = 256;
/// Return all entries matching criteria passed in message content.
pub const NLM_F_MATCH: u16 = 512;
/// Return an atomic snapshot of the table. Requires `CAP_NET_ADMIN` capability or a effective UID
/// of 0.
pub const NLM_F_ATOMIC: u16 = 1024;
pub const NLM_F_DUMP: u16 = 768;
/// Replace existing matching object.
pub const NLM_F_REPLACE: u16 = 256;
/// Don't replace if the object already exists.
pub const NLM_F_EXCL: u16 = 512;
/// Create object if it doesn't already exist.
pub const NLM_F_CREATE: u16 = 1024;
/// Add to the end of the object list.
pub const NLM_F_APPEND: u16 = 2048;

/// Do not delete recursively
pub const NLM_F_NONREC: u16 = 256;
/// request was capped
pub const NLM_F_CAPPED: u16 = 256;
/// extended ACK TVLs were included
pub const NLM_F_ACK_TLVS: u16 = 512;

// Routing/neighbour discovery messages.
pub const RTM_BASE: u16 = 16;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;
pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_DELQDISC: u16 = 37;
pub const RTM_GETQDISC: u16 = 38;
pub const RTM_NEWTCLASS: u16 = 40;
pub const RTM_DELTCLASS: u16 = 41;
pub const RTM_GETTCLASS: u16 = 42;
pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;
pub const RTM_NEWACTION: u16 = 48;
pub const RTM_DELACTION: u16 = 49;
pub const RTM_GETACTION: u16 = 50;
pub const RTM_NEWPREFIX: u16 = 52;
pub const RTM_GETMULTICAST: u16 = 58;
pub const RTM_GETANYCAST: u16 = 62;
pub const RTM_NEWNEIGHTBL: u16 = 64;
pub const RTM_GETNEIGHTBL: u16 = 66;
pub const RTM_SETNEIGHTBL: u16 = 67;
pub const RTM_NEWNDUSEROPT: u16 = 68;
pub const RTM_NEWADDRLABEL: u16 = 72;
pub const RTM_DELADDRLABEL: u16 = 73;
pub const RTM_GETADDRLABEL: u16 = 74;
pub const RTM_GETDCB: u16 = 78;
pub const RTM_SETDCB: u16 = 79;
pub const RTM_NEWNETCONF: u16 = 80;
pub const RTM_DELNETCONF: u16 = 81;
pub const RTM_GETNETCONF: u16 = 82;
pub const RTM_NEWMDB: u16 = 84;
pub const RTM_DELMDB: u16 = 85;
pub const RTM_GETMDB: u16 = 86;
pub const RTM_NEWNSID: u16 = 88;
pub const RTM_DELNSID: u16 = 89;
pub const RTM_GETNSID: u16 = 90;
pub const RTM_NEWSTATS: u16 = 92;
pub const RTM_GETSTATS: u16 = 94;
pub const RTM_NEWCACHEREPORT: u16 = 96;

pub const AF_UNSPEC: u16 = libc::AF_UNSPEC as u16;
pub const AF_UNIX: u16 = libc::AF_UNIX as u16;
// pub const AF_LOCAL: u16 = libc::AF_LOCAL as u16;
pub const AF_INET: u16 = libc::AF_INET as u16;
pub const AF_AX25: u16 = libc::AF_AX25 as u16;
pub const AF_IPX: u16 = libc::AF_IPX as u16;
pub const AF_APPLETALK: u16 = libc::AF_APPLETALK as u16;
pub const AF_NETROM: u16 = libc::AF_NETROM as u16;
pub const AF_BRIDGE: u16 = libc::AF_BRIDGE as u16;
pub const AF_ATMPVC: u16 = libc::AF_ATMPVC as u16;
pub const AF_X25: u16 = libc::AF_X25 as u16;
pub const AF_INET6: u16 = libc::AF_INET6 as u16;
pub const AF_ROSE: u16 = libc::AF_ROSE as u16;
pub const AF_DECNET: u16 = libc::AF_DECnet as u16;
pub const AF_NETBEUI: u16 = libc::AF_NETBEUI as u16;
pub const AF_SECURITY: u16 = libc::AF_SECURITY as u16;
pub const AF_KEY: u16 = libc::AF_KEY as u16;
pub const AF_NETLINK: u16 = libc::AF_NETLINK as u16;
// pub const AF_ROUTE: u16 = libc::AF_ROUTE as u16;
pub const AF_PACKET: u16 = libc::AF_PACKET as u16;
pub const AF_ASH: u16 = libc::AF_ASH as u16;
pub const AF_ECONET: u16 = libc::AF_ECONET as u16;
pub const AF_ATMSVC: u16 = libc::AF_ATMSVC as u16;
pub const AF_RDS: u16 = libc::AF_RDS as u16;
pub const AF_SNA: u16 = libc::AF_SNA as u16;
pub const AF_IRDA: u16 = libc::AF_IRDA as u16;
pub const AF_PPPOX: u16 = libc::AF_PPPOX as u16;
pub const AF_WANPIPE: u16 = libc::AF_WANPIPE as u16;
pub const AF_LLC: u16 = libc::AF_LLC as u16;
pub const AF_CAN: u16 = libc::AF_CAN as u16;
pub const AF_TIPC: u16 = libc::AF_TIPC as u16;
pub const AF_BLUETOOTH: u16 = libc::AF_BLUETOOTH as u16;
pub const AF_IUCV: u16 = libc::AF_IUCV as u16;
pub const AF_RXRPC: u16 = libc::AF_RXRPC as u16;
pub const AF_ISDN: u16 = libc::AF_ISDN as u16;
pub const AF_PHONET: u16 = libc::AF_PHONET as u16;
pub const AF_IEEE802154: u16 = libc::AF_IEEE802154 as u16;
pub const AF_CAIF: u16 = libc::AF_CAIF as u16;
pub const AF_ALG: u16 = libc::AF_ALG as u16;

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

pub const IFA_UNSPEC: u16 = 0;
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;
pub const IFA_BROADCAST: u16 = 4;
pub const IFA_ANYCAST: u16 = 5;
pub const IFA_CACHEINFO: u16 = 6;
pub const IFA_MULTICAST: u16 = 7;
pub const IFA_FLAGS: u16 = 8;

pub const IFLA_BR_UNSPEC: u16 = 0;
pub const IFLA_BR_FORWARD_DELAY: u16 = 1;
pub const IFLA_BR_HELLO_TIME: u16 = 2;
pub const IFLA_BR_MAX_AGE: u16 = 3;
pub const IFLA_BR_AGEING_TIME: u16 = 4;
pub const IFLA_BR_STP_STATE: u16 = 5;
pub const IFLA_BR_PRIORITY: u16 = 6;
pub const IFLA_BR_VLAN_FILTERING: u16 = 7;
pub const IFLA_BR_VLAN_PROTOCOL: u16 = 8;
pub const IFLA_BR_GROUP_FWD_MASK: u16 = 9;
pub const IFLA_BR_ROOT_ID: u16 = 10;
pub const IFLA_BR_BRIDGE_ID: u16 = 11;
pub const IFLA_BR_ROOT_PORT: u16 = 12;
pub const IFLA_BR_ROOT_PATH_COST: u16 = 13;
pub const IFLA_BR_TOPOLOGY_CHANGE: u16 = 14;
pub const IFLA_BR_TOPOLOGY_CHANGE_DETECTED: u16 = 15;
pub const IFLA_BR_HELLO_TIMER: u16 = 16;
pub const IFLA_BR_TCN_TIMER: u16 = 17;
pub const IFLA_BR_TOPOLOGY_CHANGE_TIMER: u16 = 18;
pub const IFLA_BR_GC_TIMER: u16 = 19;
pub const IFLA_BR_GROUP_ADDR: u16 = 20;
pub const IFLA_BR_FDB_FLUSH: u16 = 21;
pub const IFLA_BR_MCAST_ROUTER: u16 = 22;
pub const IFLA_BR_MCAST_SNOOPING: u16 = 23;
pub const IFLA_BR_MCAST_QUERY_USE_IFADDR: u16 = 24;
pub const IFLA_BR_MCAST_QUERIER: u16 = 25;
pub const IFLA_BR_MCAST_HASH_ELASTICITY: u16 = 26;
pub const IFLA_BR_MCAST_HASH_MAX: u16 = 27;
pub const IFLA_BR_MCAST_LAST_MEMBER_CNT: u16 = 28;
pub const IFLA_BR_MCAST_STARTUP_QUERY_CNT: u16 = 29;
pub const IFLA_BR_MCAST_LAST_MEMBER_INTVL: u16 = 30;
pub const IFLA_BR_MCAST_MEMBERSHIP_INTVL: u16 = 31;
pub const IFLA_BR_MCAST_QUERIER_INTVL: u16 = 32;
pub const IFLA_BR_MCAST_QUERY_INTVL: u16 = 33;
pub const IFLA_BR_MCAST_QUERY_RESPONSE_INTVL: u16 = 34;
pub const IFLA_BR_MCAST_STARTUP_QUERY_INTVL: u16 = 35;
pub const IFLA_BR_NF_CALL_IPTABLES: u16 = 36;
pub const IFLA_BR_NF_CALL_IP6TABLES: u16 = 37;
pub const IFLA_BR_NF_CALL_ARPTABLES: u16 = 38;
pub const IFLA_BR_VLAN_DEFAULT_PVID: u16 = 39;
pub const IFLA_BR_PAD: u16 = 40;
pub const IFLA_BR_VLAN_STATS_ENABLED: u16 = 41;
pub const IFLA_BR_MCAST_STATS_ENABLED: u16 = 42;
pub const IFLA_BR_MCAST_IGMP_VERSION: u16 = 43;
pub const IFLA_BR_MCAST_MLD_VERSION: u16 = 44;

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

/// Link is up (administratively).
pub const IFF_UP: u32 = libc::IFF_UP as u32;
/// Link is up and carrier is OK (RFC2863 OPER_UP)
pub const IFF_RUNNING: u32 = libc::IFF_RUNNING as u32;
/// Link layer is operational
pub const IFF_LOWER_UP: u32 = libc::IFF_LOWER_UP as u32;
/// Driver signals IFF_DORMANT
pub const IFF_DORMANT: u32 = libc::IFF_DORMANT as u32;
/// Link supports broadcasting
pub const IFF_BROADCAST: u32 = libc::IFF_BROADCAST as u32;
/// Link supports multicasting
pub const IFF_MULTICAST: u32 = libc::IFF_MULTICAST as u32;
/// Link supports multicast routing
pub const IFF_ALLMULTI: u32 = libc::IFF_ALLMULTI as u32;
/// Tell driver to do debugging (currently unused)
pub const IFF_DEBUG: u32 = libc::IFF_DEBUG as u32;
/// Link loopback network
pub const IFF_LOOPBACK: u32 = libc::IFF_LOOPBACK as u32;
/// u32erface is point-to-point link
pub const IFF_POINTOPOINT: u32 = libc::IFF_POINTOPOINT as u32;
/// ARP is not supported
pub const IFF_NOARP: u32 = libc::IFF_NOARP as u32;
/// Receive all packets.
pub const IFF_PROMISC: u32 = libc::IFF_PROMISC as u32;
/// Master of a load balancer (bonding)
pub const IFF_MASTER: u32 = libc::IFF_MASTER as u32;
/// Slave of a load balancer
pub const IFF_SLAVE: u32 = libc::IFF_SLAVE as u32;
/// Link selects port automatically (only used by ARM ethernet)
pub const IFF_PORTSEL: u32 = libc::IFF_PORTSEL as u32;
/// Driver supports setting media type (only used by ARM ethernet)
pub const IFF_AUTOMEDIA: u32 = libc::IFF_AUTOMEDIA as u32;
/// Echo sent packets (testing feature, CAN only)
pub const IFF_ECHO: u32 = libc::IFF_ECHO as u32;
/// Dialup device with changing addresses (unused, BSD compatibility)
pub const IFF_DYNAMIC: u32 = libc::IFF_DYNAMIC as u32;
/// Avoid use of trailers (unused, BSD compatibility)
pub const IFF_NOTRAILERS: u32 = libc::IFF_NOTRAILERS as u32;

/// Unknown route
pub const RTN_UNSPEC: u8 = 0;
/// A gateway or direct route
pub const RTN_UNICAST: u8 = 1;
/// A local interface route
pub const RTN_LOCAL: u8 = 2;
/// A local broadcast route (sent as a broadcast)
pub const RTN_BROADCAST: u8 = 3;
/// A local broadcast route (sent as a unicast)
pub const RTN_ANYCAST: u8 = 4;
/// A multicast route
pub const RTN_MULTICAST: u8 = 5;
/// A packet dropping route
pub const RTN_BLACKHOLE: u8 = 6;
/// An unreachable destination
pub const RTN_UNREACHABLE: u8 = 7;
/// A packet rejection route
pub const RTN_PROHIBIT: u8 = 8;
/// Continue routing lookup in another table
pub const RTN_THROW: u8 = 9;
/// A network address translation rule
pub const RTN_NAT: u8 = 10;
/// Refer to an external resolver (not implemented)
pub const RTN_XRESOLVE: u8 = 11;

/// Unknown
pub const RTPROT_UNSPEC: u8 = 0;
/// Route was learnt by an ICMP redirect
pub const RTPROT_REDIRECT: u8 = 1;
/// Route was learnt by the kernel
pub const RTPROT_KERNEL: u8 = 2;
/// Route was learnt during boot
pub const RTPROT_BOOT: u8 = 3;
/// Route was set statically
pub const RTPROT_STATIC: u8 = 4;
pub const RTPROT_GATED: u8 = 8;
pub const RTPROT_RA: u8 = 9;
pub const RTPROT_MRT: u8 = 10;
pub const RTPROT_ZEBRA: u8 = 11;
pub const RTPROT_BIRD: u8 = 12;
pub const RTPROT_DNROUTED: u8 = 13;
pub const RTPROT_XORP: u8 = 14;
pub const RTPROT_NTK: u8 = 15;
pub const RTPROT_DHCP: u8 = 16;
pub const RTPROT_MROUTED: u8 = 17;
pub const RTPROT_BABEL: u8 = 42;

/// Global route
pub const RT_SCOPE_UNIVERSE: u8 = 0;
/// Interior route in the local autonomous system
pub const RT_SCOPE_SITE: u8 = 200;
/// Route on this link
pub const RT_SCOPE_LINK: u8 = 253;
/// Route on the local host
pub const RT_SCOPE_HOST: u8 = 254;
/// Destination doesn't exist
pub const RT_SCOPE_NOWHERE: u8 = 255;

pub const RT_TABLE_UNSPEC: u8 = 0;
pub const RT_TABLE_COMPAT: u8 = 252;
pub const RT_TABLE_DEFAULT: u8 = 253;
pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;

pub const RTM_F_NOTIFY: u32 = 256;
pub const RTM_F_CLONED: u32 = 512;
pub const RTM_F_EQUALIZE: u32 = 1024;
pub const RTM_F_PREFIX: u32 = 2048;
pub const RTM_F_LOOKUP_TABLE: u32 = 4096;
pub const RTM_F_FIB_MATCH: u32 = 8192;

pub const RTA_UNSPEC: u16 = 0;
pub const RTA_DST: u16 = 1;
pub const RTA_SRC: u16 = 2;
pub const RTA_IIF: u16 = 3;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_METRICS: u16 = 8;
pub const RTA_MULTIPATH: u16 = 9;
pub const RTA_PROTOINFO: u16 = 10;
pub const RTA_FLOW: u16 = 11;
pub const RTA_CACHEINFO: u16 = 12;
pub const RTA_SESSION: u16 = 13;
pub const RTA_MP_ALGO: u16 = 14;
pub const RTA_TABLE: u16 = 15;
pub const RTA_MARK: u16 = 16;
pub const RTA_MFC_STATS: u16 = 17;
pub const RTA_VIA: u16 = 18;
pub const RTA_NEWDST: u16 = 19;
pub const RTA_PREF: u16 = 20;
pub const RTA_ENCAP_TYPE: u16 = 21;
pub const RTA_ENCAP: u16 = 22;
pub const RTA_EXPIRES: u16 = 23;
pub const RTA_PAD: u16 = 24;
pub const RTA_UID: u16 = 25;
pub const RTA_TTL_PROPAGATE: u16 = 26;

pub const RTAX_UNSPEC: u16 = 0;
pub const RTAX_LOCK: u16 = 1;
pub const RTAX_MTU: u16 = 2;
pub const RTAX_WINDOW: u16 = 3;
pub const RTAX_RTT: u16 = 4;
pub const RTAX_RTTVAR: u16 = 5;
pub const RTAX_SSTHRESH: u16 = 6;
pub const RTAX_CWND: u16 = 7;
pub const RTAX_ADVMSS: u16 = 8;
pub const RTAX_REORDERING: u16 = 9;
pub const RTAX_HOPLIMIT: u16 = 10;
pub const RTAX_INITCWND: u16 = 11;
pub const RTAX_FEATURES: u16 = 12;
pub const RTAX_RTO_MIN: u16 = 13;
pub const RTAX_INITRWND: u16 = 14;
pub const RTAX_QUICKACK: u16 = 15;
pub const RTAX_CC_ALGO: u16 = 16;
pub const RTAX_FASTOPEN_NO_COOKIE: u16 = 17;

pub const IF_OPER_UNKNOWN: u8 = 0;
pub const IF_OPER_NOTPRESENT: u8 = 1;
pub const IF_OPER_DOWN: u8 = 2;
pub const IF_OPER_LOWERLAYERDOWN: u8 = 3;
pub const IF_OPER_TESTING: u8 = 4;
pub const IF_OPER_DORMANT: u8 = 5;
pub const IF_OPER_UP: u8 = 6;

pub const IFLA_INFO_UNSPEC: u16 = 0;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;
pub const IFLA_INFO_XSTATS: u16 = 3;
pub const IFLA_INFO_SLAVE_KIND: u16 = 4;
pub const IFLA_INFO_SLAVE_DATA: u16 = 5;

pub const IFLA_VLAN_UNSPEC: u16 = 0;
pub const IFLA_VLAN_ID: u16 = 1;
pub const IFLA_VLAN_FLAGS: u16 = 2;
pub const IFLA_VLAN_EGRESS_QOS: u16 = 3;
pub const IFLA_VLAN_INGRESS_QOS: u16 = 4;
pub const IFLA_VLAN_PROTOCOL: u16 = 5;

pub const EM_NONE: u32 = 0;
pub const EM_M32: u32 = 1;
pub const EM_SPARC: u32 = 2;
pub const EM_386: u32 = 3;
pub const EM_68K: u32 = 4;
pub const EM_88K: u32 = 5;
pub const EM_486: u32 = 6;
pub const EM_860: u32 = 7;
pub const EM_MIPS: u32 = 8;
pub const EM_MIPS_RS3_LE: u32 = 10;
pub const EM_MIPS_RS4_BE: u32 = 10;
pub const EM_PARISC: u32 = 15;
pub const EM_SPARC32PLUS: u32 = 18;
pub const EM_PPC: u32 = 20;
pub const EM_PPC64: u32 = 21;
pub const EM_SPU: u32 = 23;
pub const EM_ARM: u32 = 40;
pub const EM_SH: u32 = 42;
pub const EM_SPARCV9: u32 = 43;
pub const EM_H8_300: u32 = 46;
pub const EM_IA_64: u32 = 50;
pub const EM_X86_64: u32 = 62;
pub const EM_S390: u32 = 22;
pub const EM_CRIS: u32 = 76;
pub const EM_M32R: u32 = 88;
pub const EM_MN10300: u32 = 89;
pub const EM_OPENRISC: u32 = 92;
pub const EM_BLACKFIN: u32 = 106;
pub const EM_ALTERA_NIOS2: u32 = 113;
pub const EM_TI_C6000: u32 = 140;
pub const EM_AARCH64: u32 = 183;
pub const EM_TILEPRO: u32 = 188;
pub const EM_MICROBLAZE: u32 = 189;
pub const EM_TILEGX: u32 = 191;
pub const EM_BPF: u32 = 247;
pub const EM_FRV: u32 = 21569;
pub const EM_ALPHA: u32 = 36902;
pub const EM_CYGNUS_M32R: u32 = 36929;
pub const EM_S390_OLD: u32 = 41872;
pub const EM_CYGNUS_MN10300: u32 = 48879;

// ==========================================
// 1000 - 1099 are for commanding the audit system
// ==========================================

/// Get status
pub const AUDIT_GET: u16 = 1000;
/// Set status (enable/disable/auditd)
pub const AUDIT_SET: u16 = 1001;
/// List syscall rules -- deprecated
pub const AUDIT_LIST: u16 = 1002;
/// Add syscall rule -- deprecated
pub const AUDIT_ADD: u16 = 1003;
/// Delete syscall rule -- deprecated
pub const AUDIT_DEL: u16 = 1004;
/// Message from userspace -- deprecated
pub const AUDIT_USER: u16 = 1005;
/// Define the login id and information
pub const AUDIT_LOGIN: u16 = 1006;
/// Insert file/dir watch entry
pub const AUDIT_WATCH_INS: u16 = 1007;
/// Remove file/dir watch entry
pub const AUDIT_WATCH_REM: u16 = 1008;
/// List all file/dir watches
pub const AUDIT_WATCH_LIST: u16 = 1009;
/// Get info about sender of signal to auditd
pub const AUDIT_SIGNAL_INFO: u16 = 1010;
/// Add syscall filtering rule
pub const AUDIT_ADD_RULE: u16 = 1011;
/// Delete syscall filtering rule
pub const AUDIT_DEL_RULE: u16 = 1012;
/// List syscall filtering rules
pub const AUDIT_LIST_RULES: u16 = 1013;
/// Trim junk from watched tree
pub const AUDIT_TRIM: u16 = 1014;
/// Append to watched tree
pub const AUDIT_MAKE_EQUIV: u16 = 1015;
/// Get TTY auditing status
pub const AUDIT_TTY_GET: u16 = 1016;
/// Set TTY auditing status
pub const AUDIT_TTY_SET: u16 = 1017;
/// Turn an audit feature on or off
pub const AUDIT_SET_FEATURE: u16 = 1018;
/// Get which features are enabled
pub const AUDIT_GET_FEATURE: u16 = 1019;

// ==========================================
// 1100 - 1199 user space trusted application messages
// ==========================================

/// Userspace messages mostly uninteresting to kernel
pub const AUDIT_FIRST_USER_MSG: u16 = 1100;
/// We filter this differently
pub const AUDIT_USER_AVC: u16 = 1107;
/// Non-ICANON TTY input meaning
pub const AUDIT_USER_TTY: u16 = 1124;
pub const AUDIT_LAST_USER_MSG: u16 = 1199;

/// More user space messages;
pub const AUDIT_FIRST_USER_MSG2: u16 = 2100;
pub const AUDIT_LAST_USER_MSG2: u16 = 2999;

// ==========================================
// 1200 - 1299 messages internal to the audit daemon
// ==========================================

/// Daemon startup record
pub const AUDIT_DAEMON_START: u16 = 1200;
/// Daemon normal stop record
pub const AUDIT_DAEMON_END: u16 = 1201;
/// Daemon error stop record
pub const AUDIT_DAEMON_ABORT: u16 = 1202;
/// Daemon config change
pub const AUDIT_DAEMON_CONFIG: u16 = 1203;

// ==========================================
// 1300 - 1399 audit event messages
// ==========================================

pub const AUDIT_EVENT_MESSAGE_MIN: u16 = 1300;
pub const AUDIT_EVENT_MESSAGE_MAX: u16 = 1399;
/// Syscall event
pub const AUDIT_SYSCALL: u16 = 1300;
/// Filename path information
pub const AUDIT_PATH: u16 = 1302;
/// IPC record
pub const AUDIT_IPC: u16 = 1303;
/// sys_socketcall arguments
pub const AUDIT_SOCKETCALL: u16 = 1304;
/// Audit system configuration change
pub const AUDIT_CONFIG_CHANGE: u16 = 1305;
/// sockaddr copied as syscall arg
pub const AUDIT_SOCKADDR: u16 = 1306;
/// Current working directory
pub const AUDIT_CWD: u16 = 1307;
/// execve arguments
pub const AUDIT_EXECVE: u16 = 1309;
/// IPC new permissions record type
pub const AUDIT_IPC_SET_PERM: u16 = 1311;
/// POSIX MQ open record type
pub const AUDIT_MQ_OPEN: u16 = 1312;
/// POSIX MQ send/receive record type
pub const AUDIT_MQ_SENDRECV: u16 = 1313;
/// POSIX MQ notify record type
pub const AUDIT_MQ_NOTIFY: u16 = 1314;
/// POSIX MQ get/set attribute record type
pub const AUDIT_MQ_GETSETATTR: u16 = 1315;
/// For use by 3rd party modules
pub const AUDIT_KERNEL_OTHER: u16 = 1316;
/// audit record for pipe/socketpair
pub const AUDIT_FD_PAIR: u16 = 1317;
/// ptrace target
pub const AUDIT_OBJ_PID: u16 = 1318;
/// Input on an administrative TTY
pub const AUDIT_TTY: u16 = 1319;
/// End of multi-record event
pub const AUDIT_EOE: u16 = 1320;
/// Information about fcaps increasing perms
pub const AUDIT_BPRM_FCAPS: u16 = 1321;
/// Record showing argument to sys_capset
pub const AUDIT_CAPSET: u16 = 1322;
/// Record showing descriptor and flags in mmap
pub const AUDIT_MMAP: u16 = 1323;
/// Packets traversing netfilter chains
pub const AUDIT_NETFILTER_PKT: u16 = 1324;
/// Netfilter chain modifications
pub const AUDIT_NETFILTER_CFG: u16 = 1325;
/// Secure Computing event
pub const AUDIT_SECCOMP: u16 = 1326;
/// Proctitle emit event
pub const AUDIT_PROCTITLE: u16 = 1327;
/// audit log listing feature changes
pub const AUDIT_FEATURE_CHANGE: u16 = 1328;
/// Replace auditd if this packet unanswerd
pub const AUDIT_REPLACE: u16 = 1329;
/// Kernel Module events
pub const AUDIT_KERN_MODULE: u16 = 1330;
/// Fanotify access decision
pub const AUDIT_FANOTIFY: u16 = 1331;

// ==========================================
// 1400 - 1499 SE Linux use
// ==========================================

/// SE Linux avc denial or grant
pub const AUDIT_AVC: u16 = 1400;
/// Internal SE Linux Errors
pub const AUDIT_SELINUX_ERR: u16 = 1401;
/// dentry, vfsmount pair from avc
pub const AUDIT_AVC_PATH: u16 = 1402;
/// Policy file load
pub const AUDIT_MAC_POLICY_LOAD: u16 = 1403;
/// Changed enforcing,permissive,off
pub const AUDIT_MAC_STATUS: u16 = 1404;
/// Changes to booleans
pub const AUDIT_MAC_CONFIG_CHANGE: u16 = 1405;
/// NetLabel: allow unlabeled traffic
pub const AUDIT_MAC_UNLBL_ALLOW: u16 = 1406;
/// NetLabel: add CIPSOv4 DOI entry
pub const AUDIT_MAC_CIPSOV4_ADD: u16 = 1407;
/// NetLabel: del CIPSOv4 DOI entry
pub const AUDIT_MAC_CIPSOV4_DEL: u16 = 1408;
/// NetLabel: add LSM domain mapping
pub const AUDIT_MAC_MAP_ADD: u16 = 1409;
/// NetLabel: del LSM domain mapping
pub const AUDIT_MAC_MAP_DEL: u16 = 1410;
/// Not used
pub const AUDIT_MAC_IPSEC_ADDSA: u16 = 1411;
/// Not used
pub const AUDIT_MAC_IPSEC_DELSA: u16 = 1412;
/// Not used
pub const AUDIT_MAC_IPSEC_ADDSPD: u16 = 1413;
/// Not used
pub const AUDIT_MAC_IPSEC_DELSPD: u16 = 1414;
/// Audit an IPSec event
pub const AUDIT_MAC_IPSEC_EVENT: u16 = 1415;
/// NetLabel: add a static label
pub const AUDIT_MAC_UNLBL_STCADD: u16 = 1416;
/// NetLabel: del a static label
pub const AUDIT_MAC_UNLBL_STCDEL: u16 = 1417;
/// NetLabel: add CALIPSO DOI entry
pub const AUDIT_MAC_CALIPSO_ADD: u16 = 1418;
/// NetLabel: del CALIPSO DOI entry
pub const AUDIT_MAC_CALIPSO_DEL: u16 = 1419;

// ==========================================
// 1700 - 1799 kernel anomaly records
// ==========================================

pub const AUDIT_FIRST_KERN_ANOM_MSG: u16 = 1700;
pub const AUDIT_LAST_KERN_ANOM_MSG: u16 = 1799;
/// Device changed promiscuous mode
pub const AUDIT_ANOM_PROMISCUOUS: u16 = 1700;
/// Process ended abnormally
pub const AUDIT_ANOM_ABEND: u16 = 1701;
/// Suspicious use of file links
pub const AUDIT_ANOM_LINK: u16 = 1702;

// ==========================================
// 1800 - 1899 kernel integrity events
// ==========================================

/// Data integrity verification
pub const AUDIT_INTEGRITY_DATA: u16 = 1800;
/// Metadata integrity verification
pub const AUDIT_INTEGRITY_METADATA: u16 = 1801;
/// Integrity enable status
pub const AUDIT_INTEGRITY_STATUS: u16 = 1802;
/// Integrity HASH type
pub const AUDIT_INTEGRITY_HASH: u16 = 1803;
/// PCR invalidation msgs
pub const AUDIT_INTEGRITY_PCR: u16 = 1804;
/// policy rule
pub const AUDIT_INTEGRITY_RULE: u16 = 1805;

// 2000 is for otherwise unclassified kernel audit messages (legacy)
pub const AUDIT_KERNEL: u16 = 2000;

// rule flags

/// Apply rule to user-generated messages
pub const AUDIT_FILTER_USER: u32 = 0;
/// Apply rule at task creation (not syscall)
pub const AUDIT_FILTER_TASK: u32 = 1;
/// Apply rule at syscall entry
pub const AUDIT_FILTER_ENTRY: u32 = 2;
/// Apply rule to file system watches
pub const AUDIT_FILTER_WATCH: u32 = 3;
/// Apply rule at syscall exit
pub const AUDIT_FILTER_EXIT: u32 = 4;
/// Apply rule at audit_log_start
pub const AUDIT_FILTER_TYPE: u32 = 5;

pub const AUDIT_FILTER_FS: u32 = 6;

/// Mask to get actual filter
pub const AUDIT_NR_FILTERS: u32 = 7;
pub const AUDIT_FILTER_PREPEND: u32 = 16;
/// Filter is unset
pub const AUDIT_FILTER_UNSET: u32 = 128;

// Rule actions

/// Do not build context if rule matches
pub const AUDIT_NEVER: u32 = 0;
/// Build context if rule matches
pub const AUDIT_POSSIBLE: u32 = 1;
/// Generate audit record if rule matches
pub const AUDIT_ALWAYS: u32 = 2;

pub const AUDIT_MAX_FIELDS: usize = 64;
pub const AUDIT_MAX_KEY_LEN: usize = 256;
pub const AUDIT_BITMASK_SIZE: usize = 64;

pub const AUDIT_SYSCALL_CLASSES: u32 = 16;
pub const AUDIT_CLASS_DIR_WRITE: u32 = 0;
pub const AUDIT_CLASS_DIR_WRITE_32: u32 = 1;
pub const AUDIT_CLASS_CHATTR: u32 = 2;
pub const AUDIT_CLASS_CHATTR_32: u32 = 3;
pub const AUDIT_CLASS_READ: u32 = 4;
pub const AUDIT_CLASS_READ_32: u32 = 5;
pub const AUDIT_CLASS_WRITE: u32 = 6;
pub const AUDIT_CLASS_WRITE_32: u32 = 7;
pub const AUDIT_CLASS_SIGNAL: u32 = 8;
pub const AUDIT_CLASS_SIGNAL_32: u32 = 9;
pub const AUDIT_UNUSED_BITS: u32 = 134216704;

// Field Comparing Constants
pub const AUDIT_COMPARE_UID_TO_OBJ_UID: u32 = 1;
pub const AUDIT_COMPARE_GID_TO_OBJ_GID: u32 = 2;
pub const AUDIT_COMPARE_EUID_TO_OBJ_UID: u32 = 3;
pub const AUDIT_COMPARE_EGID_TO_OBJ_GID: u32 = 4;
pub const AUDIT_COMPARE_AUID_TO_OBJ_UID: u32 = 5;
pub const AUDIT_COMPARE_SUID_TO_OBJ_UID: u32 = 6;
pub const AUDIT_COMPARE_SGID_TO_OBJ_GID: u32 = 7;
pub const AUDIT_COMPARE_FSUID_TO_OBJ_UID: u32 = 8;
pub const AUDIT_COMPARE_FSGID_TO_OBJ_GID: u32 = 9;
pub const AUDIT_COMPARE_UID_TO_AUID: u32 = 10;
pub const AUDIT_COMPARE_UID_TO_EUID: u32 = 11;
pub const AUDIT_COMPARE_UID_TO_FSUID: u32 = 12;
pub const AUDIT_COMPARE_UID_TO_SUID: u32 = 13;
pub const AUDIT_COMPARE_AUID_TO_FSUID: u32 = 14;
pub const AUDIT_COMPARE_AUID_TO_SUID: u32 = 15;
pub const AUDIT_COMPARE_AUID_TO_EUID: u32 = 16;
pub const AUDIT_COMPARE_EUID_TO_SUID: u32 = 17;
pub const AUDIT_COMPARE_EUID_TO_FSUID: u32 = 18;
pub const AUDIT_COMPARE_SUID_TO_FSUID: u32 = 19;
pub const AUDIT_COMPARE_GID_TO_EGID: u32 = 20;
pub const AUDIT_COMPARE_GID_TO_FSGID: u32 = 21;
pub const AUDIT_COMPARE_GID_TO_SGID: u32 = 22;
pub const AUDIT_COMPARE_EGID_TO_FSGID: u32 = 23;
pub const AUDIT_COMPARE_EGID_TO_SGID: u32 = 24;
pub const AUDIT_COMPARE_SGID_TO_FSGID: u32 = 25;
pub const AUDIT_MAX_FIELD_COMPARE: u32 = 25;

// =======================================================================
// rule fields
// =======================================================================
pub const AUDIT_PID: u32 = 0;
pub const AUDIT_UID: u32 = 1;
pub const AUDIT_EUID: u32 = 2;
pub const AUDIT_SUID: u32 = 3;
pub const AUDIT_FSUID: u32 = 4;
pub const AUDIT_GID: u32 = 5;
pub const AUDIT_EGID: u32 = 6;
pub const AUDIT_SGID: u32 = 7;
pub const AUDIT_FSGID: u32 = 8;
pub const AUDIT_LOGINUID: u32 = 9;
pub const AUDIT_PERS: u32 = 10;
pub const AUDIT_ARCH: u32 = 11;
pub const AUDIT_MSGTYPE: u32 = 12;
pub const AUDIT_SUBJ_USER: u32 = 13;
pub const AUDIT_SUBJ_ROLE: u32 = 14;
pub const AUDIT_SUBJ_TYPE: u32 = 15;
pub const AUDIT_SUBJ_SEN: u32 = 16;
pub const AUDIT_SUBJ_CLR: u32 = 17;
pub const AUDIT_PPID: u32 = 18;
pub const AUDIT_OBJ_USER: u32 = 19;
pub const AUDIT_OBJ_ROLE: u32 = 20;
pub const AUDIT_OBJ_TYPE: u32 = 21;
pub const AUDIT_OBJ_LEV_LOW: u32 = 22;
pub const AUDIT_OBJ_LEV_HIGH: u32 = 23;
pub const AUDIT_LOGINUID_SET: u32 = 24;
pub const AUDIT_SESSIONID: u32 = 25;
pub const AUDIT_FSTYPE: u32 = 26;
pub const AUDIT_DEVMAJOR: u32 = 100;
pub const AUDIT_DEVMINOR: u32 = 101;
pub const AUDIT_INODE: u32 = 102;
pub const AUDIT_EXIT: u32 = 103;
pub const AUDIT_SUCCESS: u32 = 104;
pub const AUDIT_WATCH: u32 = 105;
pub const AUDIT_PERM: u32 = 106;
pub const AUDIT_DIR: u32 = 107;
pub const AUDIT_FILETYPE: u32 = 108;
pub const AUDIT_OBJ_UID: u32 = 109;
pub const AUDIT_OBJ_GID: u32 = 110;
pub const AUDIT_FIELD_COMPARE: u32 = 111;
pub const AUDIT_EXE: u32 = 112;
pub const AUDIT_ARG0: u32 = 200;
pub const AUDIT_ARG1: u32 = 201;
pub const AUDIT_ARG2: u32 = 202;
pub const AUDIT_ARG3: u32 = 203;
pub const AUDIT_FILTERKEY: u32 = 210;

pub const AUDIT_BIT_MASK: u32 = 0x0800_0000;
pub const AUDIT_LESS_THAN: u32 = 0x1000_0000;
pub const AUDIT_GREATER_THAN: u32 = 0x2000_0000;
pub const AUDIT_NOT_EQUAL: u32 = 0x3000_0000;
pub const AUDIT_EQUAL: u32 = 0x4000_0000;
pub const AUDIT_BIT_TEST: u32 = AUDIT_BIT_MASK | AUDIT_EQUAL;
pub const AUDIT_LESS_THAN_OR_EQUAL: u32 = AUDIT_LESS_THAN | AUDIT_EQUAL;
pub const AUDIT_GREATER_THAN_OR_EQUAL: u32 = AUDIT_GREATER_THAN | AUDIT_EQUAL;
pub const AUDIT_OPERATORS: u32 = AUDIT_EQUAL | AUDIT_NOT_EQUAL | AUDIT_BIT_MASK;

// ==========================================
// mask values
// ==========================================
pub const AUDIT_STATUS_ENABLED: u32 = 1;
pub const AUDIT_STATUS_FAILURE: u32 = 2;
pub const AUDIT_STATUS_PID: u32 = 4;
pub const AUDIT_STATUS_RATE_LIMIT: u32 = 8;
pub const AUDIT_STATUS_BACKLOG_LIMIT: u32 = 16;
pub const AUDIT_STATUS_BACKLOG_WAIT_TIME: u32 = 32;
pub const AUDIT_STATUS_LOST: u32 = 64;
pub const AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT: u32 = 1;
pub const AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME: u32 = 2;
pub const AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH: u32 = 4;
pub const AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND: u32 = 8;
pub const AUDIT_FEATURE_BITMAP_SESSIONID_FILTER: u32 = 16;
pub const AUDIT_FEATURE_BITMAP_LOST_RESET: u32 = 32;
pub const AUDIT_FEATURE_BITMAP_FILTER_FS: u32 = 64;
pub const AUDIT_FEATURE_BITMAP_ALL: u32 = 127;
pub const AUDIT_VERSION_LATEST: u32 = 127;
pub const AUDIT_VERSION_BACKLOG_LIMIT: u32 = 1;
pub const AUDIT_VERSION_BACKLOG_WAIT_TIME: u32 = 2;

// ============================================
// failure to log actions
// ============================================
pub const AUDIT_FAIL_SILENT: u32 = 0;
pub const AUDIT_FAIL_PRINTK: u32 = 1;
pub const AUDIT_FAIL_PANIC: u32 = 2;

pub const __AUDIT_ARCH_CONVENTION_MASK: u32 = 0x3000_0000;
pub const __AUDIT_ARCH_CONVENTION_MIPS64_N32: u32 = 0x2000_0000;
pub const __AUDIT_ARCH_64BIT: u32 = 0x0800_0000;
pub const __AUDIT_ARCH_LE: u32 = 0x4000_0000;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
pub const AUDIT_ARCH_ALPHA: u32 = 0xC000_9026;
pub const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
pub const AUDIT_ARCH_ARMEB: u32 = 0x28;
pub const AUDIT_ARCH_CRIS: u32 = 0x4000_004C;
pub const AUDIT_ARCH_FRV: u32 = 0x5441;
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
pub const AUDIT_ARCH_IA64: u32 = 0xC000_0032;
pub const AUDIT_ARCH_M32R: u32 = 0x58;
pub const AUDIT_ARCH_M68K: u32 = 0x04;
pub const AUDIT_ARCH_MICROBLAZE: u32 = 0xBD;
pub const AUDIT_ARCH_MIPS: u32 = 0x08;
pub const AUDIT_ARCH_MIPSEL: u32 = 0x4000_0008;
pub const AUDIT_ARCH_MIPS64: u32 = 0x8000_0008;
pub const AUDIT_ARCH_MIPS64N32: u32 = 0xA000_0008;
pub const AUDIT_ARCH_MIPSEL64: u32 = 0xC000_0008;
pub const AUDIT_ARCH_MIPSEL64N32: u32 = 0xE000_0008;
pub const AUDIT_ARCH_OPENRISC: u32 = 92;
pub const AUDIT_ARCH_PARISC: u32 = 15;
pub const AUDIT_ARCH_PARISC64: u32 = 0x8000_000F;
pub const AUDIT_ARCH_PPC: u32 = 20;
pub const AUDIT_ARCH_PPC64: u32 = 0x8000_0015;
pub const AUDIT_ARCH_PPC64LE: u32 = 0xC000_0015;
pub const AUDIT_ARCH_S390: u32 = 22;
pub const AUDIT_ARCH_S390X: u32 = 0x8000_0016;
pub const AUDIT_ARCH_SH: u32 = 42;
pub const AUDIT_ARCH_SHEL: u32 = 0x4000_002A;
pub const AUDIT_ARCH_SH64: u32 = 0x8000_002A;
pub const AUDIT_ARCH_SHEL64: u32 = 0xC000_002A;
pub const AUDIT_ARCH_SPARC: u32 = 2;
pub const AUDIT_ARCH_SPARC64: u32 = 0x8000_002B;
pub const AUDIT_ARCH_TILEGX: u32 = 0xC000_00BF;
pub const AUDIT_ARCH_TILEGX32: u32 = 0x4000_00BF;
pub const AUDIT_ARCH_TILEPRO: u32 = 0x4000_00BC;
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_PERM_EXEC: u32 = 1;
pub const AUDIT_PERM_WRITE: u32 = 2;
pub const AUDIT_PERM_READ: u32 = 4;
pub const AUDIT_PERM_ATTR: u32 = 8;
pub const AUDIT_MESSAGE_TEXT_MAX: u32 = 8560;
pub const AUDIT_FEATURE_VERSION: u32 = 1;
pub const AUDIT_FEATURE_ONLY_UNSET_LOGINUID: u32 = 0;
pub const AUDIT_FEATURE_LOGINUID_IMMUTABLE: u32 = 1;
pub const AUDIT_LAST_FEATURE: u32 = 1;

/// Unused multicast group for audit
pub const AUDIT_NLGRP_NONE: u32 = 0;
/// Multicast group to listen for audit events
pub const AUDIT_NLGRP_READLOG: u32 = 1;

pub const NLMSGERR_ATTR_UNUSED: int = 0;
pub const NLMSGERR_ATTR_MSG: int = 1;
pub const NLMSGERR_ATTR_OFFS: int = 2;
pub const NLMSGERR_ATTR_COOKIE: int = 3;
pub const NLMSGERR_ATTR_MAX: int = 3;

pub const NL_MMAP_STATUS_UNUSED: int = 0;
pub const NL_MMAP_STATUS_RESERVED: int = 1;
pub const NL_MMAP_STATUS_VALID: int = 2;
pub const NL_MMAP_STATUS_COPY: int = 3;
pub const NL_MMAP_STATUS_SKIP: int = 4;

pub const NETLINK_UNCONNECTED: int = 0;
pub const NETLINK_CONNECTED: int = 1;

pub const IN6_ADDR_GEN_MODE_EUI64: int = 0;
pub const IN6_ADDR_GEN_MODE_NONE: int = 1;
pub const IN6_ADDR_GEN_MODE_STABLE_PRIVACY: int = 2;
pub const IN6_ADDR_GEN_MODE_RANDOM: int = 3;

pub const BRIDGE_MODE_UNSPEC: int = 0;
pub const BRIDGE_MODE_HAIRPIN: int = 1;

pub const IFLA_BRPORT_UNSPEC: int = 0;
pub const IFLA_BRPORT_STATE: int = 1;
pub const IFLA_BRPORT_PRIORITY: int = 2;
pub const IFLA_BRPORT_COST: int = 3;
pub const IFLA_BRPORT_MODE: int = 4;
pub const IFLA_BRPORT_GUARD: int = 5;
pub const IFLA_BRPORT_PROTECT: int = 6;
pub const IFLA_BRPORT_FAST_LEAVE: int = 7;
pub const IFLA_BRPORT_LEARNING: int = 8;
pub const IFLA_BRPORT_UNICAST_FLOOD: int = 9;
pub const IFLA_BRPORT_PROXYARP: int = 10;
pub const IFLA_BRPORT_LEARNING_SYNC: int = 11;
pub const IFLA_BRPORT_PROXYARP_WIFI: int = 12;
pub const IFLA_BRPORT_ROOT_ID: int = 13;
pub const IFLA_BRPORT_BRIDGE_ID: int = 14;
pub const IFLA_BRPORT_DESIGNATED_PORT: int = 15;
pub const IFLA_BRPORT_DESIGNATED_COST: int = 16;
pub const IFLA_BRPORT_ID: int = 17;
pub const IFLA_BRPORT_NO: int = 18;
pub const IFLA_BRPORT_TOPOLOGY_CHANGE_ACK: int = 19;
pub const IFLA_BRPORT_CONFIG_PENDING: int = 20;
pub const IFLA_BRPORT_MESSAGE_AGE_TIMER: int = 21;
pub const IFLA_BRPORT_FORWARD_DELAY_TIMER: int = 22;
pub const IFLA_BRPORT_HOLD_TIMER: int = 23;
pub const IFLA_BRPORT_FLUSH: int = 24;
pub const IFLA_BRPORT_MULTICAST_ROUTER: int = 25;
pub const IFLA_BRPORT_PAD: int = 26;
pub const IFLA_BRPORT_MCAST_FLOOD: int = 27;
pub const IFLA_BRPORT_MCAST_TO_UCAST: int = 28;
pub const IFLA_BRPORT_VLAN_TUNNEL: int = 29;
pub const IFLA_BRPORT_BCAST_FLOOD: int = 30;
pub const IFLA_BRPORT_GROUP_FWD_MASK: int = 31;
pub const IFLA_BRPORT_NEIGH_SUPPRESS: int = 32;

pub const IFLA_VLAN_QOS_UNSPEC: int = 0;
pub const IFLA_VLAN_QOS_MAPPING: int = 1;

pub const IFLA_MACVLAN_UNSPEC: int = 0;
pub const IFLA_MACVLAN_MODE: int = 1;
pub const IFLA_MACVLAN_FLAGS: int = 2;
pub const IFLA_MACVLAN_MACADDR_MODE: int = 3;
pub const IFLA_MACVLAN_MACADDR: int = 4;
pub const IFLA_MACVLAN_MACADDR_DATA: int = 5;
pub const IFLA_MACVLAN_MACADDR_COUNT: int = 6;

pub const MACVLAN_MODE_PRIVATE: int = 1;
pub const MACVLAN_MODE_VEPA: int = 2;
pub const MACVLAN_MODE_BRIDGE: int = 4;
pub const MACVLAN_MODE_PASSTHRU: int = 8;
pub const MACVLAN_MODE_SOURCE: int = 16;

pub const MACVLAN_MACADDR_ADD: int = 0;
pub const MACVLAN_MACADDR_DEL: int = 1;
pub const MACVLAN_MACADDR_FLUSH: int = 2;
pub const MACVLAN_MACADDR_SET: int = 3;

pub const IFLA_VRF_UNSPEC: int = 0;
pub const IFLA_VRF_TABLE: int = 1;

pub const IFLA_VRF_PORT_UNSPEC: int = 0;
pub const IFLA_VRF_PORT_TABLE: int = 1;

pub const IFLA_MACSEC_UNSPEC: int = 0;
pub const IFLA_MACSEC_SCI: int = 1;
pub const IFLA_MACSEC_PORT: int = 2;
pub const IFLA_MACSEC_ICV_LEN: int = 3;
pub const IFLA_MACSEC_CIPHER_SUITE: int = 4;
pub const IFLA_MACSEC_WINDOW: int = 5;
pub const IFLA_MACSEC_ENCODING_SA: int = 6;
pub const IFLA_MACSEC_ENCRYPT: int = 7;
pub const IFLA_MACSEC_PROTECT: int = 8;
pub const IFLA_MACSEC_INC_SCI: int = 9;
pub const IFLA_MACSEC_ES: int = 10;
pub const IFLA_MACSEC_SCB: int = 11;
pub const IFLA_MACSEC_REPLAY_PROTECT: int = 12;
pub const IFLA_MACSEC_VALIDATION: int = 13;
pub const IFLA_MACSEC_PAD: int = 14;

pub const MACSEC_VALIDATE_DISABLED: int = 0;
pub const MACSEC_VALIDATE_CHECK: int = 1;
pub const MACSEC_VALIDATE_STRICT: int = 2;
pub const MACSEC_VALIDATE_MAX: int = 2;

pub const IFLA_IPVLAN_UNSPEC: int = 0;
pub const IFLA_IPVLAN_MODE: int = 1;
pub const IFLA_IPVLAN_FLAGS: int = 2;

pub const IPVLAN_MODE_L2: int = 0;
pub const IPVLAN_MODE_L3: int = 1;
pub const IPVLAN_MODE_L3S: int = 2;
pub const IPVLAN_MODE_MAX: int = 3;

pub const IFLA_VXLAN_UNSPEC: int = 0;
pub const IFLA_VXLAN_ID: int = 1;
pub const IFLA_VXLAN_GROUP: int = 2;
pub const IFLA_VXLAN_LINK: int = 3;
pub const IFLA_VXLAN_LOCAL: int = 4;
pub const IFLA_VXLAN_TTL: int = 5;
pub const IFLA_VXLAN_TOS: int = 6;
pub const IFLA_VXLAN_LEARNING: int = 7;
pub const IFLA_VXLAN_AGEING: int = 8;
pub const IFLA_VXLAN_LIMIT: int = 9;
pub const IFLA_VXLAN_PORT_RANGE: int = 10;
pub const IFLA_VXLAN_PROXY: int = 11;
pub const IFLA_VXLAN_RSC: int = 12;
pub const IFLA_VXLAN_L2MISS: int = 13;
pub const IFLA_VXLAN_L3MISS: int = 14;
pub const IFLA_VXLAN_PORT: int = 15;
pub const IFLA_VXLAN_GROUP6: int = 16;
pub const IFLA_VXLAN_LOCAL6: int = 17;
pub const IFLA_VXLAN_UDP_CSUM: int = 18;
pub const IFLA_VXLAN_UDP_ZERO_CSUM6_TX: int = 19;
pub const IFLA_VXLAN_UDP_ZERO_CSUM6_RX: int = 20;
pub const IFLA_VXLAN_REMCSUM_TX: int = 21;
pub const IFLA_VXLAN_REMCSUM_RX: int = 22;
pub const IFLA_VXLAN_GBP: int = 23;
pub const IFLA_VXLAN_REMCSUM_NOPARTIAL: int = 24;
pub const IFLA_VXLAN_COLLECT_METADATA: int = 25;
pub const IFLA_VXLAN_LABEL: int = 26;
pub const IFLA_VXLAN_GPE: int = 27;

pub const IFLA_GENEVE_UNSPEC: int = 0;
pub const IFLA_GENEVE_ID: int = 1;
pub const IFLA_GENEVE_REMOTE: int = 2;
pub const IFLA_GENEVE_TTL: int = 3;
pub const IFLA_GENEVE_TOS: int = 4;
pub const IFLA_GENEVE_PORT: int = 5;
pub const IFLA_GENEVE_COLLECT_METADATA: int = 6;
pub const IFLA_GENEVE_REMOTE6: int = 7;
pub const IFLA_GENEVE_UDP_CSUM: int = 8;
pub const IFLA_GENEVE_UDP_ZERO_CSUM6_TX: int = 9;
pub const IFLA_GENEVE_UDP_ZERO_CSUM6_RX: int = 10;
pub const IFLA_GENEVE_LABEL: int = 11;

pub const IFLA_PPP_UNSPEC: int = 0;
pub const IFLA_PPP_DEV_FD: int = 1;

pub const GTP_ROLE_GGSN: int = 0;
pub const GTP_ROLE_SGSN: int = 1;

pub const IFLA_GTP_UNSPEC: int = 0;
pub const IFLA_GTP_FD0: int = 1;
pub const IFLA_GTP_FD1: int = 2;
pub const IFLA_GTP_PDP_HASHSIZE: int = 3;
pub const IFLA_GTP_ROLE: int = 4;

pub const IFLA_BOND_UNSPEC: int = 0;
pub const IFLA_BOND_MODE: int = 1;
pub const IFLA_BOND_ACTIVE_SLAVE: int = 2;
pub const IFLA_BOND_MIIMON: int = 3;
pub const IFLA_BOND_UPDELAY: int = 4;
pub const IFLA_BOND_DOWNDELAY: int = 5;
pub const IFLA_BOND_USE_CARRIER: int = 6;
pub const IFLA_BOND_ARP_INTERVAL: int = 7;
pub const IFLA_BOND_ARP_IP_TARGET: int = 8;
pub const IFLA_BOND_ARP_VALIDATE: int = 9;
pub const IFLA_BOND_ARP_ALL_TARGETS: int = 10;
pub const IFLA_BOND_PRIMARY: int = 11;
pub const IFLA_BOND_PRIMARY_RESELECT: int = 12;
pub const IFLA_BOND_FAIL_OVER_MAC: int = 13;
pub const IFLA_BOND_XMIT_HASH_POLICY: int = 14;
pub const IFLA_BOND_RESEND_IGMP: int = 15;
pub const IFLA_BOND_NUM_PEER_NOTIF: int = 16;
pub const IFLA_BOND_ALL_SLAVES_ACTIVE: int = 17;
pub const IFLA_BOND_MIN_LINKS: int = 18;
pub const IFLA_BOND_LP_INTERVAL: int = 19;
pub const IFLA_BOND_PACKETS_PER_SLAVE: int = 20;
pub const IFLA_BOND_AD_LACP_RATE: int = 21;
pub const IFLA_BOND_AD_SELECT: int = 22;
pub const IFLA_BOND_AD_INFO: int = 23;
pub const IFLA_BOND_AD_ACTOR_SYS_PRIO: int = 24;
pub const IFLA_BOND_AD_USER_PORT_KEY: int = 25;
pub const IFLA_BOND_AD_ACTOR_SYSTEM: int = 26;
pub const IFLA_BOND_TLB_DYNAMIC_LB: int = 27;

pub const IFLA_BOND_AD_INFO_UNSPEC: int = 0;
pub const IFLA_BOND_AD_INFO_AGGREGATOR: int = 1;
pub const IFLA_BOND_AD_INFO_NUM_PORTS: int = 2;
pub const IFLA_BOND_AD_INFO_ACTOR_KEY: int = 3;
pub const IFLA_BOND_AD_INFO_PARTNER_KEY: int = 4;
pub const IFLA_BOND_AD_INFO_PARTNER_MAC: int = 5;

pub const IFLA_BOND_SLAVE_UNSPEC: int = 0;
pub const IFLA_BOND_SLAVE_STATE: int = 1;
pub const IFLA_BOND_SLAVE_MII_STATUS: int = 2;
pub const IFLA_BOND_SLAVE_LINK_FAILURE_COUNT: int = 3;
pub const IFLA_BOND_SLAVE_PERM_HWADDR: int = 4;
pub const IFLA_BOND_SLAVE_QUEUE_ID: int = 5;
pub const IFLA_BOND_SLAVE_AD_AGGREGATOR_ID: int = 6;
pub const IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE: int = 7;
pub const IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE: int = 8;

pub const IFLA_VF_INFO_UNSPEC: int = 0;
pub const IFLA_VF_INFO: int = 1;

pub const IFLA_VF_UNSPEC: int = 0;
pub const IFLA_VF_MAC: int = 1;
pub const IFLA_VF_VLAN: int = 2;
pub const IFLA_VF_TX_RATE: int = 3;
pub const IFLA_VF_SPOOFCHK: int = 4;
pub const IFLA_VF_LINK_STATE: int = 5;
pub const IFLA_VF_RATE: int = 6;
pub const IFLA_VF_RSS_QUERY_EN: int = 7;
pub const IFLA_VF_STATS: int = 8;
pub const IFLA_VF_TRUST: int = 9;
pub const IFLA_VF_IB_NODE_GUID: int = 10;
pub const IFLA_VF_IB_PORT_GUID: int = 11;
pub const IFLA_VF_VLAN_LIST: int = 12;

pub const IFLA_VF_VLAN_INFO_UNSPEC: int = 0;
pub const IFLA_VF_VLAN_INFO: int = 1;

pub const TCA_ROOT_UNSPEC: int = 0;
pub const TCA_ROOT_TAB: int = 1;
pub const TCA_ROOT_FLAGS: int = 2;
pub const TCA_ROOT_COUNT: int = 3;
pub const TCA_ROOT_TIME_DELTA: int = 4;

pub const NDUSEROPT_UNSPEC: int = 0;
pub const NDUSEROPT_SRCADDR: int = 1;

pub const RTNLGRP_NONE: int = 0;
pub const RTNLGRP_LINK: int = 1;
pub const RTNLGRP_NOTIFY: int = 2;
pub const RTNLGRP_NEIGH: int = 3;
pub const RTNLGRP_TC: int = 4;
pub const RTNLGRP_IPV4_IFADDR: int = 5;
pub const RTNLGRP_IPV4_MROUTE: int = 6;
pub const RTNLGRP_IPV4_ROUTE: int = 7;
pub const RTNLGRP_IPV4_RULE: int = 8;
pub const RTNLGRP_IPV6_IFADDR: int = 9;
pub const RTNLGRP_IPV6_MROUTE: int = 10;
pub const RTNLGRP_IPV6_ROUTE: int = 11;
pub const RTNLGRP_IPV6_IFINFO: int = 12;
pub const RTNLGRP_DECNET_IFADDR: int = 13;
pub const RTNLGRP_NOP2: int = 14;
pub const RTNLGRP_DECNET_ROUTE: int = 15;
pub const RTNLGRP_DECNET_RULE: int = 16;
pub const RTNLGRP_NOP4: int = 17;
pub const RTNLGRP_IPV6_PREFIX: int = 18;
pub const RTNLGRP_IPV6_RULE: int = 19;
pub const RTNLGRP_ND_USEROPT: int = 20;
pub const RTNLGRP_PHONET_IFADDR: int = 21;
pub const RTNLGRP_PHONET_ROUTE: int = 22;
pub const RTNLGRP_DCB: int = 23;
pub const RTNLGRP_IPV4_NETCONF: int = 24;
pub const RTNLGRP_IPV6_NETCONF: int = 25;
pub const RTNLGRP_MDB: int = 26;
pub const RTNLGRP_MPLS_ROUTE: int = 27;
pub const RTNLGRP_NSID: int = 28;
pub const RTNLGRP_MPLS_NETCONF: int = 29;
pub const RTNLGRP_IPV4_MROUTE_R: int = 30;
pub const RTNLGRP_IPV6_MROUTE_R: int = 31;

pub const IFLA_VF_LINK_STATE_AUTO: int = 0;
pub const IFLA_VF_LINK_STATE_ENABLE: int = 1;
pub const IFLA_VF_LINK_STATE_DISABLE: int = 2;

pub const IFLA_VF_STATS_RX_PACKETS: int = 0;
pub const IFLA_VF_STATS_TX_PACKETS: int = 1;
pub const IFLA_VF_STATS_RX_BYTES: int = 2;
pub const IFLA_VF_STATS_TX_BYTES: int = 3;
pub const IFLA_VF_STATS_BROADCAST: int = 4;
pub const IFLA_VF_STATS_MULTICAST: int = 5;
pub const IFLA_VF_STATS_PAD: int = 6;
pub const IFLA_VF_STATS_RX_DROPPED: int = 7;
pub const IFLA_VF_STATS_TX_DROPPED: int = 8;

pub const IFLA_VF_PORT_UNSPEC: int = 0;
pub const IFLA_VF_PORT: int = 1;

pub const IFLA_PORT_UNSPEC: int = 0;
pub const IFLA_PORT_VF: int = 1;
pub const IFLA_PORT_PROFILE: int = 2;
pub const IFLA_PORT_VSI_TYPE: int = 3;
pub const IFLA_PORT_INSTANCE_UUID: int = 4;
pub const IFLA_PORT_HOST_UUID: int = 5;
pub const IFLA_PORT_REQUEST: int = 6;
pub const IFLA_PORT_RESPONSE: int = 7;

pub const PORT_REQUEST_PREASSOCIATE: int = 0;
pub const PORT_REQUEST_PREASSOCIATE_RR: int = 1;
pub const PORT_REQUEST_ASSOCIATE: int = 2;
pub const PORT_REQUEST_DISASSOCIATE: int = 3;

pub const PORT_VDP_RESPONSE_SUCCESS: int = 0;
pub const PORT_VDP_RESPONSE_INVALID_FORMAT: int = 1;
pub const PORT_VDP_RESPONSE_INSUFFICIENT_RESOURCES: int = 2;
pub const PORT_VDP_RESPONSE_UNUSED_VTID: int = 3;
pub const PORT_VDP_RESPONSE_VTID_VIOLATION: int = 4;
pub const PORT_VDP_RESPONSE_VTID_VERSION_VIOALTION: int = 5;
pub const PORT_VDP_RESPONSE_OUT_OF_SYNC: int = 6;
pub const PORT_PROFILE_RESPONSE_SUCCESS: int = 256;
pub const PORT_PROFILE_RESPONSE_INPROGRESS: int = 257;
pub const PORT_PROFILE_RESPONSE_INVALID: int = 258;
pub const PORT_PROFILE_RESPONSE_BADSTATE: int = 259;
pub const PORT_PROFILE_RESPONSE_INSUFFICIENT_RESOURCES: int = 260;
pub const PORT_PROFILE_RESPONSE_ERROR: int = 261;

pub const IFLA_IPOIB_UNSPEC: int = 0;
pub const IFLA_IPOIB_PKEY: int = 1;
pub const IFLA_IPOIB_MODE: int = 2;
pub const IFLA_IPOIB_UMCAST: int = 3;

pub const IPOIB_MODE_DATAGRAM: int = 0;
pub const IPOIB_MODE_CONNECTED: int = 1;

pub const IFLA_HSR_UNSPEC: int = 0;
pub const IFLA_HSR_SLAVE1: int = 1;
pub const IFLA_HSR_SLAVE2: int = 2;
pub const IFLA_HSR_MULTICAST_SPEC: int = 3;
pub const IFLA_HSR_SUPERVISION_ADDR: int = 4;
pub const IFLA_HSR_SEQ_NR: int = 5;
pub const IFLA_HSR_VERSION: int = 6;

pub const IFLA_STATS_UNSPEC: int = 0;
pub const IFLA_STATS_LINK_64: int = 1;
pub const IFLA_STATS_LINK_XSTATS: int = 2;
pub const IFLA_STATS_LINK_XSTATS_SLAVE: int = 3;
pub const IFLA_STATS_LINK_OFFLOAD_XSTATS: int = 4;
pub const IFLA_STATS_AF_SPEC: int = 5;

pub const LINK_XSTATS_TYPE_UNSPEC: int = 0;
pub const LINK_XSTATS_TYPE_BRIDGE: int = 1;

pub const IFLA_OFFLOAD_XSTATS_UNSPEC: int = 0;
pub const IFLA_OFFLOAD_XSTATS_CPU_HIT: int = 1;

pub const XDP_ATTACHED_NONE: int = 0;
pub const XDP_ATTACHED_DRV: int = 1;
pub const XDP_ATTACHED_SKB: int = 2;
pub const XDP_ATTACHED_HW: int = 3;

pub const IFLA_XDP_UNSPEC: int = 0;
pub const IFLA_XDP_FD: int = 1;
pub const IFLA_XDP_ATTACHED: int = 2;
pub const IFLA_XDP_FLAGS: int = 3;
pub const IFLA_XDP_PROG_ID: int = 4;

pub const IFLA_EVENT_NONE: int = 0;
pub const IFLA_EVENT_REBOOT: int = 1;
pub const IFLA_EVENT_FEATURES: int = 2;
pub const IFLA_EVENT_BONDING_FAILOVER: int = 3;
pub const IFLA_EVENT_NOTIFY_PEERS: int = 4;
pub const IFLA_EVENT_IGMP_RESEND: int = 5;
pub const IFLA_EVENT_BONDING_OPTIONS: int = 6;

pub const NDA_UNSPEC: u16 = 0;
pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;
pub const NDA_CACHEINFO: u16 = 3;
pub const NDA_PROBES: u16 = 4;
pub const NDA_VLAN: u16 = 5;
pub const NDA_PORT: u16 = 6;
pub const NDA_VNI: u16 = 7;
pub const NDA_IFINDEX: u16 = 8;
pub const NDA_MASTER: u16 = 9;
pub const NDA_LINK_NETNSID: u16 = 10;
pub const NDA_SRC_VNI: u16 = 11;

pub const NDTPA_UNSPEC: int = 0;
pub const NDTPA_IFINDEX: int = 1;
pub const NDTPA_REFCNT: int = 2;
pub const NDTPA_REACHABLE_TIME: int = 3;
pub const NDTPA_BASE_REACHABLE_TIME: int = 4;
pub const NDTPA_RETRANS_TIME: int = 5;
pub const NDTPA_GC_STALETIME: int = 6;
pub const NDTPA_DELAY_PROBE_TIME: int = 7;
pub const NDTPA_QUEUE_LEN: int = 8;
pub const NDTPA_APP_PROBES: int = 9;
pub const NDTPA_UCAST_PROBES: int = 10;
pub const NDTPA_MCAST_PROBES: int = 11;
pub const NDTPA_ANYCAST_DELAY: int = 12;
pub const NDTPA_PROXY_DELAY: int = 13;
pub const NDTPA_PROXY_QLEN: int = 14;
pub const NDTPA_LOCKTIME: int = 15;
pub const NDTPA_QUEUE_LENBYTES: int = 16;
pub const NDTPA_MCAST_REPROBES: int = 17;
pub const NDTPA_PAD: int = 18;

pub const NDTA_UNSPEC: u16 = 0;
pub const NDTA_NAME: u16 = 1;
pub const NDTA_THRESH1: u16 = 2;
pub const NDTA_THRESH2: u16 = 3;
pub const NDTA_THRESH3: u16 = 4;
pub const NDTA_CONFIG: u16 = 5;
pub const NDTA_PARMS: u16 = 6;
pub const NDTA_STATS: u16 = 7;
pub const NDTA_GC_INTERVAL: u16 = 8;
pub const NDTA_PAD: u16 = 9;

#[allow(overflowing_literals)]
pub const RT_TABLE_MAX: int = 4294967295;

pub const PREFIX_UNSPEC: int = 0;
pub const PREFIX_ADDRESS: int = 1;
pub const PREFIX_CACHEINFO: int = 2;

pub const TCA_UNSPEC: int = 0;
pub const TCA_KIND: int = 1;
pub const TCA_OPTIONS: int = 2;
pub const TCA_STATS: int = 3;
pub const TCA_XSTATS: int = 4;
pub const TCA_RATE: int = 5;
pub const TCA_FCNT: int = 6;
pub const TCA_STATS2: int = 7;
pub const TCA_STAB: int = 8;
pub const TCA_PAD: int = 9;
pub const TCA_DUMP_INVISIBLE: int = 10;
pub const TCA_CHAIN: int = 11;
pub const TCA_HW_OFFLOAD: int = 12;
pub const TCA_INGRESS_BLOCK: int = 13;
pub const TCA_EGRESS_BLOCK: int = 14;

pub const __BITS_PER_LONG: int = 64;
pub const __FD_SETSIZE: int = 1024;
pub const SI_LOAD_SHIFT: int = 16;
pub const _K_SS_MAXSIZE: int = 128;
pub const NETLINK_SMC: int = 22;
pub const NETLINK_INET_DIAG: int = 4;
pub const MAX_LINKS: int = 32;

pub const NLMSG_MIN_TYPE: int = 16;
pub const NETLINK_ADD_MEMBERSHIP: int = 1;
pub const NETLINK_DROP_MEMBERSHIP: int = 2;
pub const NETLINK_PKTINFO: int = 3;
pub const NETLINK_BROADCAST_ERROR: int = 4;
pub const NETLINK_NO_ENOBUFS: int = 5;
pub const NETLINK_RX_RING: int = 6;
pub const NETLINK_TX_RING: int = 7;
pub const NETLINK_LISTEN_ALL_NSID: int = 8;
pub const NETLINK_LIST_MEMBERSHIPS: int = 9;
pub const NETLINK_CAP_ACK: int = 10;
pub const NETLINK_EXT_ACK: int = 11;
pub const NL_MMAP_MSG_ALIGNMENT: int = 4;
pub const NET_MAJOR: int = 36;

pub const MACVLAN_FLAG_NOPROMISC: int = 1;
pub const IPVLAN_F_PRIVATE: int = 1;
pub const IPVLAN_F_VEPA: int = 2;
pub const MAX_VLAN_LIST_LEN: int = 1;
pub const PORT_PROFILE_MAX: int = 40;
pub const PORT_UUID_MAX: int = 16;
pub const PORT_SELF_VF: int = -1;
pub const XDP_FLAGS_UPDATE_IF_NOEXIST: int = 1;
pub const XDP_FLAGS_SKB_MODE: int = 2;
pub const XDP_FLAGS_DRV_MODE: int = 4;
pub const XDP_FLAGS_HW_MODE: int = 8;
pub const XDP_FLAGS_MODES: int = 14;
pub const XDP_FLAGS_MASK: int = 15;
pub const IFA_F_SECONDARY: int = 1;
pub const IFA_F_TEMPORARY: int = 1;
pub const IFA_F_NODAD: int = 2;
pub const IFA_F_OPTIMISTIC: int = 4;
pub const IFA_F_DADFAILED: int = 8;
pub const IFA_F_HOMEADDRESS: int = 16;
pub const IFA_F_DEPRECATED: int = 32;
pub const IFA_F_TENTATIVE: int = 64;
pub const IFA_F_PERMANENT: int = 128;
pub const IFA_F_MANAGETEMPADDR: int = 256;
pub const IFA_F_NOPREFIXROUTE: int = 512;
pub const IFA_F_MCAUTOJOIN: int = 1024;
pub const IFA_F_STABLE_PRIVACY: int = 2048;
pub const NTF_USE: u8 = 1;
pub const NTF_SELF: u8 = 2;
pub const NTF_MASTER: u8 = 4;
pub const NTF_PROXY: u8 = 8;
pub const NTF_EXT_LEARNED: u8 = 16;
pub const NTF_OFFLOADED: u8 = 32;
pub const NTF_ROUTER: u8 = 128;
pub const NUD_INCOMPLETE: u16 = 1;
pub const NUD_REACHABLE: u16 = 2;
pub const NUD_STALE: u16 = 4;
pub const NUD_DELAY: u16 = 8;
pub const NUD_PROBE: u16 = 16;
pub const NUD_FAILED: u16 = 32;
pub const NUD_NOARP: u16 = 64;
pub const NUD_PERMANENT: u16 = 128;
pub const NUD_NONE: u16 = 0;
pub const RTNL_FAMILY_IPMR: int = 128;
pub const RTNL_FAMILY_IP6MR: int = 129;
pub const RTNL_FAMILY_MAX: int = 129;
pub const RTA_ALIGNTO: int = 4;

pub const RTNH_F_DEAD: int = 1;
pub const RTNH_F_PERVASIVE: int = 2;
pub const RTNH_F_ONLINK: int = 4;
pub const RTNH_F_OFFLOAD: int = 8;
pub const RTNH_F_LINKDOWN: int = 16;
pub const RTNH_F_UNRESOLVED: int = 32;
pub const RTNH_COMPARE_MASK: int = 25;
pub const RTNH_ALIGNTO: int = 4;
pub const RTNETLINK_HAVE_PEERINFO: int = 1;
pub const RTAX_FEATURE_ECN: int = 1;
pub const RTAX_FEATURE_SACK: int = 2;
pub const RTAX_FEATURE_TIMESTAMP: int = 4;
pub const RTAX_FEATURE_ALLFRAG: int = 8;
pub const RTAX_FEATURE_MASK: int = 15;
#[allow(overflowing_literals)]
pub const TCM_IFINDEX_MAGIC_BLOCK: int = 4294967295;
pub const RTMGRP_LINK: int = 1;
pub const RTMGRP_NOTIFY: int = 2;
pub const RTMGRP_NEIGH: int = 4;
pub const RTMGRP_TC: int = 8;
pub const RTMGRP_IPV4_IFADDR: int = 16;
pub const RTMGRP_IPV4_MROUTE: int = 32;
pub const RTMGRP_IPV4_ROUTE: int = 64;
pub const RTMGRP_IPV4_RULE: int = 128;
pub const RTMGRP_IPV6_IFADDR: int = 256;
pub const RTMGRP_IPV6_MROUTE: int = 512;
pub const RTMGRP_IPV6_ROUTE: int = 1024;
pub const RTMGRP_IPV6_IFINFO: int = 2048;
pub const RTMGRP_DECNET_IFADDR: int = 4096;
pub const RTMGRP_DECNET_ROUTE: int = 16384;
pub const RTMGRP_IPV6_PREFIX: int = 131072;
pub const TCA_FLAG_LARGE_DUMP_ON: int = 1;
pub const RTEXT_FILTER_VF: int = 1;
pub const RTEXT_FILTER_BRVLAN: int = 2;
pub const RTEXT_FILTER_BRVLAN_COMPRESSED: int = 4;
pub const RTEXT_FILTER_SKIP_STATS: int = 8;
pub const ARPOP_REQUEST: int = 1;
pub const ARPOP_REPLY: int = 2;
