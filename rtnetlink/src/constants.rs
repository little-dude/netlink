#![cfg_attr(nightly, rustfmt::skip)]

use bindgen_constants as constants;

/// Constants used for the "message type" field of netlink headers, that apply to any protocol family.
mod message_types {
    use bindgen_constants as constants;
    /// The message is ignored.
    pub const NLMSG_NOOP: u16 = constants::NLMSG_NOOP as u16;
    /// The message signals an error and the payload contains a nlmsgerr structure. This can be looked
    /// at as a NACK and typically it is from FEC to CPC.
    pub const NLMSG_ERROR: u16 = constants::NLMSG_ERROR as u16;
    /// The message terminates a multipart message.
    pub const NLMSG_DONE: u16 = constants::NLMSG_DONE as u16;
    /// Data lost
    pub const NLMSG_OVERRUN: u16 = constants::NLMSG_OVERRUN as u16;
}
pub use self::message_types::*;

/// Netlink protocols
mod protocols {
    use bindgen_constants as constants;
    /// Receives routing and link updates and may be used to modify the routing tables (both IPv4
    /// and IPv6), IP addresses, link parameters, neighbor setups, queueing disciplines, traffic
    /// classes  and  packet  classifiers  (see rtnetlink(7)).
    pub const NETLINK_ROUTE: isize = constants::NETLINK_ROUTE as isize;
    pub const NETLINK_UNUSED: isize = constants::NETLINK_UNUSED as isize;
    /// Reserved for user-mode socket protocols.
    pub const NETLINK_USERSOCK: isize = constants::NETLINK_USERSOCK as isize;
    /// Transport  IPv4  packets  from  netfilter  to  user  space.  Used by ip_queue kernel
    /// module.  After a long period of being declared obsolete (in favor of the more advanced
    /// nfnetlink_queue feature), it was  removed in Linux 3.5.
    pub const NETLINK_FIREWALL: isize = constants::NETLINK_FIREWALL as isize;
    /// Query information about sockets of various protocol families from the kernel (see sock_diag(7)).
    pub const NETLINK_SOCK_DIAG: isize = constants::NETLINK_SOCK_DIAG as isize;
    /// Netfilter/iptables ULOG.
    pub const NETLINK_NFLOG: isize = constants::NETLINK_NFLOG as isize;
    /// IPsec.
    pub const NETLINK_XFRM: isize = constants::NETLINK_XFRM as isize;
    /// SELinux event notifications.
    pub const NETLINK_SELINUX: isize = constants::NETLINK_SELINUX as isize;
    /// Open-iSCSI.
    pub const NETLINK_ISCSI: isize = constants::NETLINK_ISCSI as isize;
    /// Auditing.
    pub const NETLINK_AUDIT: isize = constants::NETLINK_AUDIT as isize;
    /// Access to FIB lookup from user space.
    pub const NETLINK_FIB_LOOKUP: isize = constants::NETLINK_FIB_LOOKUP as isize;
    /// Kernel connector. See `Documentation/connector/*` in the Linux kernel source tree for further information.
    pub const NETLINK_CONNECTOR: isize = constants::NETLINK_CONNECTOR as isize;
    /// Netfilter subsystem.
    pub const NETLINK_NETFILTER: isize = constants::NETLINK_NETFILTER as isize;
    /// Transport IPv6 packets from netfilter to user space.  Used by ip6_queue kernel module.
    pub const NETLINK_IP6_FW: isize = constants::NETLINK_IP6_FW as isize;
    /// DECnet routing messages.
    pub const NETLINK_DNRTMSG: isize = constants::NETLINK_DNRTMSG as isize;
    /// Kernel messages to user space.
    pub const NETLINK_KOBJECT_UEVENT: isize = constants::NETLINK_KOBJECT_UEVENT as isize;
    ///  Generic netlink family for simplified netlink usage.
    pub const NETLINK_GENERIC: isize = constants::NETLINK_GENERIC as isize;
    /// SCSI transpots
    pub const NETLINK_SCSITRANSPORT: isize = constants::NETLINK_SCSITRANSPORT as isize;
    ///
    pub const NETLINK_ECRYPTFS: isize = constants::NETLINK_ECRYPTFS as isize;
    /// Infiniband RDMA.
    pub const NETLINK_RDMA: isize = constants::NETLINK_RDMA as isize;
    /// Netlink interface to request information about ciphers registered with the kernel crypto
    /// API as well as allow configuration of the kernel crypto API.
    pub const NETLINK_CRYPTO: isize = constants::NETLINK_CRYPTO as isize;
}
pub use self::protocols::*;

/// Identify the bits that represent the type of a netlink attribute.
pub const NLA_TYPE_MASK: u16 = (constants::NLA_TYPE_MASK & 0xFFFF) as u16;
/// Identify the bits that represent the "nested" flag of a netlink attribute.
pub const NLA_F_NESTED: u16 = (constants::NLA_F_NESTED & 0xFFFF) as u16;
/// Identify the bits that represent the "byte order" flag of a netlink attribute.
pub const NLA_F_NET_BYTEORDER: u16 = (constants::NLA_F_NET_BYTEORDER & 0xFFFF) as u16;

/// Constants used for the "message type" field of netlink headers. These values are specific to
/// the `NETLINK_ROUTE` protocol family.
mod rtnl_message_types {
    use bindgen_constants as constants;
    pub const RTM_NEWLINK: u16 = constants::RTM_NEWLINK as u16;
    pub const RTM_DELLINK: u16 = constants::RTM_DELLINK as u16;
    pub const RTM_GETLINK: u16 = constants::RTM_GETLINK as u16;
    pub const RTM_SETLINK: u16 = constants::RTM_SETLINK as u16;
    pub const RTM_NEWADDR: u16 = constants::RTM_NEWADDR as u16;
    pub const RTM_DELADDR: u16 = constants::RTM_DELADDR as u16;
    pub const RTM_GETADDR: u16 = constants::RTM_GETADDR as u16;
    pub const RTM_NEWROUTE: u16 = constants::RTM_NEWROUTE as u16;
    pub const RTM_DELROUTE: u16 = constants::RTM_DELROUTE as u16;
    pub const RTM_GETROUTE: u16 = constants::RTM_GETROUTE as u16;
    pub const RTM_NEWNEIGH: u16 = constants::RTM_NEWNEIGH as u16;
    pub const RTM_DELNEIGH: u16 = constants::RTM_DELNEIGH as u16;
    pub const RTM_GETNEIGH: u16 = constants::RTM_GETNEIGH as u16;
    pub const RTM_NEWRULE: u16 = constants::RTM_NEWRULE as u16;
    pub const RTM_DELRULE: u16 = constants::RTM_DELRULE as u16;
    pub const RTM_GETRULE: u16 = constants::RTM_GETRULE as u16;
    pub const RTM_NEWQDISC: u16 = constants::RTM_NEWQDISC as u16;
    pub const RTM_DELQDISC: u16 = constants::RTM_DELQDISC as u16;
    pub const RTM_GETQDISC: u16 = constants::RTM_GETQDISC as u16;
    pub const RTM_NEWTCLASS: u16 = constants::RTM_NEWTCLASS as u16;
    pub const RTM_DELTCLASS: u16 = constants::RTM_DELTCLASS as u16;
    pub const RTM_GETTCLASS: u16 = constants::RTM_GETTCLASS as u16;
    pub const RTM_NEWTFILTER: u16 = constants::RTM_NEWTFILTER as u16;
    pub const RTM_DELTFILTER: u16 = constants::RTM_DELTFILTER as u16;
    pub const RTM_GETTFILTER: u16 = constants::RTM_GETTFILTER as u16;
    pub const RTM_NEWACTION: u16 = constants::RTM_NEWACTION as u16;
    pub const RTM_DELACTION: u16 = constants::RTM_DELACTION as u16;
    pub const RTM_GETACTION: u16 = constants::RTM_GETACTION as u16;
    pub const RTM_NEWPREFIX: u16 = constants::RTM_NEWPREFIX as u16;
    pub const RTM_GETMULTICAST: u16 = constants::RTM_GETMULTICAST as u16;
    pub const RTM_GETANYCAST: u16 = constants::RTM_GETANYCAST as u16;
    pub const RTM_NEWNEIGHTBL: u16 = constants::RTM_NEWNEIGHTBL as u16;
    pub const RTM_GETNEIGHTBL: u16 = constants::RTM_GETNEIGHTBL as u16;
    pub const RTM_SETNEIGHTBL: u16 = constants::RTM_SETNEIGHTBL as u16;
    pub const RTM_NEWNDUSEROPT: u16 = constants::RTM_NEWNDUSEROPT as u16;
    pub const RTM_NEWADDRLABEL: u16 = constants::RTM_NEWADDRLABEL as u16;
    pub const RTM_DELADDRLABEL: u16 = constants::RTM_DELADDRLABEL as u16;
    pub const RTM_GETADDRLABEL: u16 = constants::RTM_GETADDRLABEL as u16;
    pub const RTM_GETDCB: u16 = constants::RTM_GETDCB as u16;
    pub const RTM_SETDCB: u16 = constants::RTM_SETDCB as u16;
    pub const RTM_NEWNETCONF: u16 = constants::RTM_NEWNETCONF as u16;
    pub const RTM_DELNETCONF: u16 = constants::RTM_DELNETCONF as u16;
    pub const RTM_GETNETCONF: u16 = constants::RTM_GETNETCONF as u16;
    pub const RTM_NEWMDB: u16 = constants::RTM_NEWMDB as u16;
    pub const RTM_DELMDB: u16 = constants::RTM_DELMDB as u16;
    pub const RTM_GETMDB: u16 = constants::RTM_GETMDB as u16;
    pub const RTM_NEWNSID: u16 = constants::RTM_NEWNSID as u16;
    pub const RTM_DELNSID: u16 = constants::RTM_DELNSID as u16;
    pub const RTM_GETNSID: u16 = constants::RTM_GETNSID as u16;
    pub const RTM_NEWSTATS: u16 = constants::RTM_NEWSTATS as u16;
    pub const RTM_GETSTATS: u16 = constants::RTM_GETSTATS as u16;
    pub const RTM_NEWCACHEREPORT: u16 = constants::RTM_NEWCACHEREPORT as u16;
}
pub use self::rtnl_message_types::*;

/// Constants used for the "flags" field of the netlink header.
mod nl_flags {
    use bindgen_constants as constants;
    use libc;
    // Standard flag bits
    // =====================================

    /// Must be set on all request messages (typically from user space to kernel space)
    pub const NLM_F_REQUEST: u16 = libc::NLM_F_REQUEST as u16;
    ///  Indicates the message is part of a multipart message terminated by NLMSG_DONE
    pub const NLM_MULTIPART: u16 = libc::NLM_F_MULTI as u16;
    /// Request for an acknowledgment on success. Typical direction of request is from user space
    /// (CPC) to kernel space (FEC).
    pub const NLM_F_ACK: u16 = libc::NLM_F_ACK as u16;
    /// Echo this request.  Typical direction of request is from user space (CPC) to kernel space
    /// (FEC).
    pub const NLM_F_ECHO: u16 = libc::NLM_F_ECHO as u16;
    /// Dump was inconsistent due to sequence change
    pub const NLM_F_DUMP_INTR: u16 = libc::NLM_F_DUMP_INTR as u16;
    /// Dump was filtered as requested
    pub const NLM_F_DUMP_FILTERED: u16 = libc::NLM_F_DUMP_FILTERED as u16;

    // Additional flag bits for GET requests
    // =====================================

    /// Return the complete table instead of a single entry.
    pub const NLM_F_ROOT: u16 = libc::NLM_F_ROOT as u16;
    /// Return all entries matching criteria passed in message content.
    pub const NLM_F_MATCH: u16 = libc::NLM_F_MATCH as u16;
    /// Return an atomic snapshot of the table. Requires `CAP_NET_ADMIN` capability or a effective UID
    /// of 0.
    pub const NLM_F_ATOMIC: u16 = libc::NLM_F_ATOMIC as u16;

    pub const NLM_F_DUMP: u16 = libc::NLM_F_DUMP as u16;

    // Additional flag bits for NEW requests
    // =====================================

    /// Replace existing matching object.
    pub const NLM_F_REPLACE: u16 = libc::NLM_F_REPLACE as u16;
    /// Don't replace if the object already exists.
    pub const NLM_F_EXCL: u16 = libc::NLM_F_EXCL as u16;
    /// Create object if it doesn't already exist.
    pub const NLM_F_CREATE: u16 = libc::NLM_F_CREATE as u16;
    /// Add to the end of the object list.
    pub const NLM_F_APPEND: u16 = libc::NLM_F_APPEND as u16;

    // Additional flag bits for DELETE requests
    // =====================================

    /// Do not delete recursively
    pub const NLM_F_NONREC: u16 = constants::NLM_F_NONREC as u16;

    // Additional flag bits for ACK requests
    // =====================================

    /// request was capped
    pub const NLM_F_CAPPED: u16 = constants::NLM_F_CAPPED as u16;
    /// extended ACK TVLs were included
    pub const NLM_F_ACK_TLVS: u16 = constants::NLM_F_ACK_TLVS as u16;
}
pub use self::nl_flags::*;

/// Constants used in the `IFLA_AF_SPEC` attributes for the `NETLINK_ROUTE` protocol family.
mod rtnl_afspec {
    use bindgen_constants as constants;
    use libc;

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

    pub const IFLA_INET_UNSPEC: u16 = constants::IFLA_INET_UNSPEC as u16;
    pub const IFLA_INET_CONF: u16 = constants::IFLA_INET_CONF as u16;

    pub const IFLA_INET6_UNSPEC: u16 = constants::IFLA_INET6_UNSPEC as u16;
    pub const IFLA_INET6_FLAGS: u16 = constants::IFLA_INET6_FLAGS as u16;
    pub const IFLA_INET6_CONF: u16 = constants::IFLA_INET6_CONF as u16;
    pub const IFLA_INET6_STATS: u16 = constants::IFLA_INET6_STATS as u16;
    // pub const IFLA_INET6_MCAST: u16 = constants::IFLA_INET6_MCAST as u16;
    pub const IFLA_INET6_CACHEINFO: u16 = constants::IFLA_INET6_CACHEINFO as u16;
    pub const IFLA_INET6_ICMP6STATS: u16 = constants::IFLA_INET6_ICMP6STATS as u16;
    pub const IFLA_INET6_TOKEN: u16 = constants::IFLA_INET6_TOKEN as u16;
    pub const IFLA_INET6_ADDR_GEN_MODE: u16 = constants::IFLA_INET6_ADDR_GEN_MODE as u16;
}
pub use self::rtnl_afspec::*;

/// Constants used to identify the various attributes used for "address" messages of the
/// `NETLINK_ROUTE` family: `RTM_NEWADDR`, `RTM_DELADDR`, and `RTM_GETADDR`
mod rtnl_address_nlas {
    use bindgen_constants as constants;
    pub const IFA_UNSPEC: u16 = constants::IFA_UNSPEC as u16;
    pub const IFA_ADDRESS: u16 = constants::IFA_ADDRESS as u16;
    pub const IFA_LOCAL: u16 = constants::IFA_LOCAL as u16;
    pub const IFA_LABEL: u16 = constants::IFA_LABEL as u16;
    pub const IFA_BROADCAST: u16 = constants::IFA_BROADCAST as u16;
    pub const IFA_ANYCAST: u16 = constants::IFA_ANYCAST as u16;
    pub const IFA_CACHEINFO: u16 = constants::IFA_CACHEINFO as u16;
    pub const IFA_MULTICAST: u16 = constants::IFA_MULTICAST as u16;
    pub const IFA_FLAGS: u16 = constants::IFA_FLAGS as u16;
}
pub use self::rtnl_address_nlas::*;

/// Constants used to identify the various attributes used for "link" messages of the
/// `NETLINK_ROUTE` family: `RTM_NEWLINK`, `RTM_DELLINK`, `RTM_GETLINK` and `RTM_SETLINK`
mod rtnl_link_nlas {
    use bindgen_constants as constants;
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

    pub const IFLA_INFO_UNSPEC: u16 = constants::IFLA_INFO_UNSPEC as u16;
    pub const IFLA_INFO_KIND: u16 = constants::IFLA_INFO_KIND as u16;
    pub const IFLA_INFO_DATA: u16 = constants::IFLA_INFO_DATA as u16;
    pub const IFLA_INFO_XSTATS: u16 = constants::IFLA_INFO_XSTATS as u16;
    pub const IFLA_INFO_SLAVE_KIND: u16 = constants::IFLA_INFO_SLAVE_KIND as u16;
    pub const IFLA_INFO_SLAVE_DATA: u16 = constants::IFLA_INFO_SLAVE_DATA as u16;

    pub const IFLA_VLAN_UNSPEC: u16 = constants::IFLA_VLAN_UNSPEC as u16;
    pub const IFLA_VLAN_ID: u16 = constants::IFLA_VLAN_ID as u16;
    pub const IFLA_VLAN_FLAGS: u16 = constants::IFLA_VLAN_FLAGS as u16;
    pub const IFLA_VLAN_EGRESS_QOS: u16 = constants::IFLA_VLAN_EGRESS_QOS as u16;
    pub const IFLA_VLAN_INGRESS_QOS: u16 = constants::IFLA_VLAN_INGRESS_QOS as u16;
    pub const IFLA_VLAN_PROTOCOL: u16 = constants::IFLA_VLAN_PROTOCOL as u16;

    pub const IFLA_BR_UNSPEC: u16 = constants::IFLA_BR_UNSPEC as u16;
    pub const IFLA_BR_FORWARD_DELAY: u16 = constants::IFLA_BR_FORWARD_DELAY as u16;
    pub const IFLA_BR_HELLO_TIME: u16 = constants::IFLA_BR_HELLO_TIME as u16;
    pub const IFLA_BR_MAX_AGE: u16 = constants::IFLA_BR_MAX_AGE as u16;
    pub const IFLA_BR_AGEING_TIME: u16 = constants::IFLA_BR_AGEING_TIME as u16;
    pub const IFLA_BR_STP_STATE: u16 = constants::IFLA_BR_STP_STATE as u16;
    pub const IFLA_BR_PRIORITY: u16 = constants::IFLA_BR_PRIORITY as u16;
    pub const IFLA_BR_VLAN_FILTERING: u16 = constants::IFLA_BR_VLAN_FILTERING as u16;
    pub const IFLA_BR_VLAN_PROTOCOL: u16 = constants::IFLA_BR_VLAN_PROTOCOL as u16;
    pub const IFLA_BR_GROUP_FWD_MASK: u16 = constants::IFLA_BR_GROUP_FWD_MASK as u16;
    pub const IFLA_BR_ROOT_ID: u16 = constants::IFLA_BR_ROOT_ID as u16;
    pub const IFLA_BR_BRIDGE_ID: u16 = constants::IFLA_BR_BRIDGE_ID as u16;
    pub const IFLA_BR_ROOT_PORT: u16 = constants::IFLA_BR_ROOT_PORT as u16;
    pub const IFLA_BR_ROOT_PATH_COST: u16 = constants::IFLA_BR_ROOT_PATH_COST as u16;
    pub const IFLA_BR_TOPOLOGY_CHANGE: u16 = constants::IFLA_BR_TOPOLOGY_CHANGE as u16;
    pub const IFLA_BR_TOPOLOGY_CHANGE_DETECTED: u16 = constants::IFLA_BR_TOPOLOGY_CHANGE_DETECTED as u16;
    pub const IFLA_BR_HELLO_TIMER: u16 = constants::IFLA_BR_HELLO_TIMER as u16;
    pub const IFLA_BR_TCN_TIMER: u16 = constants::IFLA_BR_TCN_TIMER as u16;
    pub const IFLA_BR_TOPOLOGY_CHANGE_TIMER: u16 = constants::IFLA_BR_TOPOLOGY_CHANGE_TIMER as u16;
    pub const IFLA_BR_GC_TIMER: u16 = constants::IFLA_BR_GC_TIMER as u16;
    pub const IFLA_BR_GROUP_ADDR: u16 = constants::IFLA_BR_GROUP_ADDR as u16;
    pub const IFLA_BR_FDB_FLUSH: u16 = constants::IFLA_BR_FDB_FLUSH as u16;
    pub const IFLA_BR_MCAST_ROUTER: u16 = constants::IFLA_BR_MCAST_ROUTER as u16;
    pub const IFLA_BR_MCAST_SNOOPING: u16 = constants::IFLA_BR_MCAST_SNOOPING as u16;
    pub const IFLA_BR_MCAST_QUERY_USE_IFADDR: u16 = constants::IFLA_BR_MCAST_QUERY_USE_IFADDR as u16;
    pub const IFLA_BR_MCAST_QUERIER: u16 = constants::IFLA_BR_MCAST_QUERIER as u16;
    pub const IFLA_BR_MCAST_HASH_ELASTICITY: u16 = constants::IFLA_BR_MCAST_HASH_ELASTICITY as u16;
    pub const IFLA_BR_MCAST_HASH_MAX: u16 = constants::IFLA_BR_MCAST_HASH_MAX as u16;
    pub const IFLA_BR_MCAST_LAST_MEMBER_CNT: u16 = constants::IFLA_BR_MCAST_LAST_MEMBER_CNT as u16;
    pub const IFLA_BR_MCAST_STARTUP_QUERY_CNT: u16 = constants::IFLA_BR_MCAST_STARTUP_QUERY_CNT as u16;
    pub const IFLA_BR_MCAST_LAST_MEMBER_INTVL: u16 = constants::IFLA_BR_MCAST_LAST_MEMBER_INTVL as u16;
    pub const IFLA_BR_MCAST_MEMBERSHIP_INTVL: u16 = constants::IFLA_BR_MCAST_MEMBERSHIP_INTVL as u16;
    pub const IFLA_BR_MCAST_QUERIER_INTVL: u16 = constants::IFLA_BR_MCAST_QUERIER_INTVL as u16;
    pub const IFLA_BR_MCAST_QUERY_INTVL: u16 = constants::IFLA_BR_MCAST_QUERY_INTVL as u16;
    pub const IFLA_BR_MCAST_QUERY_RESPONSE_INTVL: u16 = constants::IFLA_BR_MCAST_QUERY_RESPONSE_INTVL as u16;
    pub const IFLA_BR_MCAST_STARTUP_QUERY_INTVL: u16 = constants::IFLA_BR_MCAST_STARTUP_QUERY_INTVL as u16;
    pub const IFLA_BR_NF_CALL_IPTABLES: u16 = constants::IFLA_BR_NF_CALL_IPTABLES as u16;
    pub const IFLA_BR_NF_CALL_IP6TABLES: u16 = constants::IFLA_BR_NF_CALL_IP6TABLES as u16;
    pub const IFLA_BR_NF_CALL_ARPTABLES: u16 = constants::IFLA_BR_NF_CALL_ARPTABLES as u16;
    pub const IFLA_BR_VLAN_DEFAULT_PVID: u16 = constants::IFLA_BR_VLAN_DEFAULT_PVID as u16;
    pub const IFLA_BR_PAD: u16 = constants::IFLA_BR_PAD as u16;
    pub const IFLA_BR_VLAN_STATS_ENABLED: u16 = constants::IFLA_BR_VLAN_STATS_ENABLED as u16;
    pub const IFLA_BR_MCAST_STATS_ENABLED: u16 = constants::IFLA_BR_MCAST_STATS_ENABLED as u16;
    pub const IFLA_BR_MCAST_IGMP_VERSION: u16 = constants::IFLA_BR_MCAST_IGMP_VERSION as u16;
    pub const IFLA_BR_MCAST_MLD_VERSION: u16 = constants::IFLA_BR_MCAST_MLD_VERSION as u16;
}
pub use self::rtnl_link_nlas::*;

/// Constants that identify the link layer type in a `NETLINK_ROUTE` packet of type `RTM_NEWLINK`,
/// `RTM_DELLINK`, `RTM_GETLINK` and `RTM_SETLINK`
mod rtnl_link_layer_type {
    use bindgen_constants as constants;
    pub const ARPHRD_NETROM: u16 = constants::ARPHRD_NETROM as u16;
    pub const ARPHRD_ETHER: u16 = constants::ARPHRD_ETHER as u16;
    pub const ARPHRD_EETHER: u16 = constants::ARPHRD_EETHER as u16;
    pub const ARPHRD_AX25: u16 = constants::ARPHRD_AX25 as u16;
    pub const ARPHRD_PRONET: u16 = constants::ARPHRD_PRONET as u16;
    pub const ARPHRD_CHAOS: u16 = constants::ARPHRD_CHAOS as u16;
    pub const ARPHRD_IEEE802: u16 = constants::ARPHRD_IEEE802 as u16;
    pub const ARPHRD_ARCNET: u16 = constants::ARPHRD_ARCNET as u16;
    pub const ARPHRD_APPLETLK: u16 = constants::ARPHRD_APPLETLK as u16;
    pub const ARPHRD_DLCI: u16 = constants::ARPHRD_DLCI as u16;
    pub const ARPHRD_ATM: u16 = constants::ARPHRD_ATM as u16;
    pub const ARPHRD_METRICOM: u16 = constants::ARPHRD_METRICOM as u16;
    pub const ARPHRD_IEEE1394: u16 = constants::ARPHRD_IEEE1394 as u16;
    pub const ARPHRD_EUI64: u16 = constants::ARPHRD_EUI64 as u16;
    pub const ARPHRD_INFINIBAND: u16 = constants::ARPHRD_INFINIBAND as u16;
    pub const ARPHRD_SLIP: u16 = constants::ARPHRD_SLIP as u16;
    pub const ARPHRD_CSLIP: u16 = constants::ARPHRD_CSLIP as u16;
    pub const ARPHRD_SLIP6: u16 = constants::ARPHRD_SLIP6 as u16;
    pub const ARPHRD_CSLIP6: u16 = constants::ARPHRD_CSLIP6 as u16;
    pub const ARPHRD_RSRVD: u16 = constants::ARPHRD_RSRVD as u16;
    pub const ARPHRD_ADAPT: u16 = constants::ARPHRD_ADAPT as u16;
    pub const ARPHRD_ROSE: u16 = constants::ARPHRD_ROSE as u16;
    pub const ARPHRD_X25: u16 = constants::ARPHRD_X25 as u16;
    pub const ARPHRD_HWX25: u16 = constants::ARPHRD_HWX25 as u16;
    pub const ARPHRD_CAN: u16 = constants::ARPHRD_CAN as u16;
    pub const ARPHRD_PPP: u16 = constants::ARPHRD_PPP as u16;
    pub const ARPHRD_HDLC: u16 = constants::ARPHRD_HDLC as u16;
    pub const ARPHRD_LAPB: u16 = constants::ARPHRD_LAPB as u16;
    pub const ARPHRD_DDCMP: u16 = constants::ARPHRD_DDCMP as u16;
    pub const ARPHRD_RAWHDLC: u16 = constants::ARPHRD_RAWHDLC as u16;
    pub const ARPHRD_RAWIP: u16 = constants::ARPHRD_RAWIP as u16;
    pub const ARPHRD_TUNNEL: u16 = constants::ARPHRD_TUNNEL as u16;
    pub const ARPHRD_TUNNEL6: u16 = constants::ARPHRD_TUNNEL6 as u16;
    pub const ARPHRD_FRAD: u16 = constants::ARPHRD_FRAD as u16;
    pub const ARPHRD_SKIP: u16 = constants::ARPHRD_SKIP as u16;
    pub const ARPHRD_LOOPBACK: u16 = constants::ARPHRD_LOOPBACK as u16;
    pub const ARPHRD_LOCALTLK: u16 = constants::ARPHRD_LOCALTLK as u16;
    pub const ARPHRD_FDDI: u16 = constants::ARPHRD_FDDI as u16;
    pub const ARPHRD_BIF: u16 = constants::ARPHRD_BIF as u16;
    pub const ARPHRD_SIT: u16 = constants::ARPHRD_SIT as u16;
    pub const ARPHRD_IPDDP: u16 = constants::ARPHRD_IPDDP as u16;
    pub const ARPHRD_IPGRE: u16 = constants::ARPHRD_IPGRE as u16;
    pub const ARPHRD_PIMREG: u16 = constants::ARPHRD_PIMREG as u16;
    pub const ARPHRD_HIPPI: u16 = constants::ARPHRD_HIPPI as u16;
    pub const ARPHRD_ASH: u16 = constants::ARPHRD_ASH as u16;
    pub const ARPHRD_ECONET: u16 = constants::ARPHRD_ECONET as u16;
    pub const ARPHRD_IRDA: u16 = constants::ARPHRD_IRDA as u16;
    pub const ARPHRD_FCPP: u16 = constants::ARPHRD_FCPP as u16;
    pub const ARPHRD_FCAL: u16 = constants::ARPHRD_FCAL as u16;
    pub const ARPHRD_FCPL: u16 = constants::ARPHRD_FCPL as u16;
    pub const ARPHRD_FCFABRIC: u16 = constants::ARPHRD_FCFABRIC as u16;
    pub const ARPHRD_IEEE802_TR: u16 = constants::ARPHRD_IEEE802_TR as u16;
    pub const ARPHRD_IEEE80211: u16 = constants::ARPHRD_IEEE80211 as u16;
    pub const ARPHRD_IEEE80211_PRISM: u16 = constants::ARPHRD_IEEE80211_PRISM as u16;
    pub const ARPHRD_IEEE80211_RADIOTAP: u16 = constants::ARPHRD_IEEE80211_RADIOTAP as u16;
    pub const ARPHRD_IEEE802154: u16 = constants::ARPHRD_IEEE802154 as u16;
    pub const ARPHRD_IEEE802154_MONITOR: u16 = constants::ARPHRD_IEEE802154_MONITOR as u16;
    pub const ARPHRD_PHONET: u16 = constants::ARPHRD_PHONET as u16;
    pub const ARPHRD_PHONET_PIPE: u16 = constants::ARPHRD_PHONET_PIPE as u16;
    pub const ARPHRD_CAIF: u16 = constants::ARPHRD_CAIF as u16;
    pub const ARPHRD_IP6GRE: u16 = constants::ARPHRD_IP6GRE as u16;
    pub const ARPHRD_NETLINK: u16 = constants::ARPHRD_NETLINK as u16;
    pub const ARPHRD_6LOWPAN: u16 = constants::ARPHRD_6LOWPAN as u16;
    pub const ARPHRD_VSOCKMON: u16 = constants::ARPHRD_VSOCKMON as u16;
    pub const ARPHRD_VOID: u16 = constants::ARPHRD_VOID as u16;
    pub const ARPHRD_NONE: u16 = constants::ARPHRD_NONE as u16;
}
pub use self::rtnl_link_layer_type::*;

mod rtnl_link_flags {
    use libc;
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
}
pub use self::rtnl_link_flags::*;

mod rtnl_route_types {
    use bindgen_constants as constants;
    /// Unknown route
    pub const RTN_UNSPEC: u8 = constants::RTN_UNSPEC as u8;
    /// A gateway or direct route
    pub const RTN_UNICAST: u8 = constants::RTN_UNICAST as u8;
    /// A local interface route
    pub const RTN_LOCAL: u8 = constants::RTN_LOCAL as u8;
    /// A local broadcast route (sent as a broadcast)
    pub const RTN_BROADCAST: u8 = constants::RTN_BROADCAST as u8;
    /// A local broadcast route (sent as a unicast)
    pub const RTN_ANYCAST: u8 = constants::RTN_ANYCAST as u8;
    /// A multicast route
    pub const RTN_MULTICAST: u8 = constants::RTN_MULTICAST as u8;
    /// A packet dropping route
    pub const RTN_BLACKHOLE: u8 = constants::RTN_BLACKHOLE as u8;
    /// An unreachable destination
    pub const RTN_UNREACHABLE: u8 = constants::RTN_UNREACHABLE as u8;
    /// A packet rejection route
    pub const RTN_PROHIBIT: u8 = constants::RTN_PROHIBIT as u8;
    /// Continue routing lookup in another table
    pub const RTN_THROW: u8 = constants::RTN_THROW as u8;
    /// A network address translation rule
    pub const RTN_NAT: u8 = constants::RTN_NAT as u8;
    /// Refer to an external resolver (not implemented)
    pub const RTN_XRESOLVE: u8 = constants::RTN_XRESOLVE as u8;
}
pub use self::rtnl_route_types::*;

mod rtnl_route_protocols {
    use bindgen_constants as constants;
    /// Unknown
    pub const RTPROT_UNSPEC: u8 = constants::RTPROT_UNSPEC as u8;
    /// Route was learnt by an ICMP redirect
    pub const RTPROT_REDIRECT: u8 = constants::RTPROT_REDIRECT as u8;
    /// Route was learnt by the kernel
    pub const RTPROT_KERNEL: u8 = constants::RTPROT_KERNEL as u8;
    /// Route was learnt during boot
    pub const RTPROT_BOOT: u8 = constants::RTPROT_BOOT as u8;
    /// Route was set statically
    pub const RTPROT_STATIC: u8 = constants::RTPROT_STATIC as u8;
    pub const RTPROT_GATED: u8 = constants::RTPROT_GATED as u8;
    pub const RTPROT_RA: u8 = constants::RTPROT_RA as u8;
    pub const RTPROT_MRT: u8 = constants::RTPROT_MRT as u8;
    pub const RTPROT_ZEBRA: u8 = constants::RTPROT_ZEBRA as u8;
    pub const RTPROT_BIRD: u8 = constants::RTPROT_BIRD as u8;
    pub const RTPROT_DNROUTED: u8 = constants::RTPROT_DNROUTED as u8;
    pub const RTPROT_XORP: u8 = constants::RTPROT_XORP as u8;
    pub const RTPROT_NTK: u8 = constants::RTPROT_NTK as u8;
    pub const RTPROT_DHCP: u8 = constants::RTPROT_DHCP as u8;
    pub const RTPROT_MROUTED: u8 = constants::RTPROT_MROUTED as u8;
    pub const RTPROT_BABEL: u8 = constants::RTPROT_BABEL as u8;
}
pub use self::rtnl_route_protocols::*;

/// Distance to the destination
mod rtnl_route_scope {
    use bindgen_constants as constants;

    /// Global route
    pub const RT_SCOPE_UNIVERSE: u8 = constants::RT_SCOPE_UNIVERSE as u8;
    /// Interior route in the local autonomous system
    pub const RT_SCOPE_SITE: u8 = constants::RT_SCOPE_SITE as u8;
    /// Route on this link
    pub const RT_SCOPE_LINK: u8 = constants::RT_SCOPE_LINK as u8;
    /// Route on the local host
    pub const RT_SCOPE_HOST: u8 = constants::RT_SCOPE_HOST as u8;
    /// Destination doesn't exist
    pub const RT_SCOPE_NOWHERE: u8 = constants::RT_SCOPE_NOWHERE as u8;
}
pub use self::rtnl_route_scope::*;

/// Routing table
mod rtnl_route_table {
    use bindgen_constants as constants;
    pub const RT_TABLE_UNSPEC: u8 = constants::RT_TABLE_UNSPEC as u8;
    pub const RT_TABLE_COMPAT: u8 = constants::RT_TABLE_COMPAT as u8;
    pub const RT_TABLE_DEFAULT: u8 = constants::RT_TABLE_DEFAULT as u8;
    pub const RT_TABLE_MAIN: u8 = constants::RT_TABLE_MAIN as u8;
    pub const RT_TABLE_LOCAL: u8 = constants::RT_TABLE_LOCAL as u8;
}
pub use self::rtnl_route_table::*;

mod rtnl_route_flags {
    use bindgen_constants as constants;
    pub const RTM_F_NOTIFY: u32 = constants::RTM_F_NOTIFY as u32;
    pub const RTM_F_CLONED: u32 = constants::RTM_F_CLONED as u32;
    pub const RTM_F_EQUALIZE: u32 = constants::RTM_F_EQUALIZE as u32;
    pub const RTM_F_PREFIX: u32 = constants::RTM_F_PREFIX as u32;
    pub const RTM_F_LOOKUP_TABLE: u32 = constants::RTM_F_LOOKUP_TABLE as u32;
    pub const RTM_F_FIB_MATCH: u32 = constants::RTM_F_FIB_MATCH as u32;
}
pub use self::rtnl_route_flags::*;

mod rtnl_route_nlas {
    use bindgen_constants as constants;

    pub const RTA_UNSPEC: u16 = constants::RTA_UNSPEC as u16;
    pub const RTA_DST: u16 = constants::RTA_DST as u16;
    pub const RTA_SRC: u16 = constants::RTA_SRC as u16;
    pub const RTA_IIF: u16 = constants::RTA_IIF as u16;
    pub const RTA_OIF: u16 = constants::RTA_OIF as u16;
    pub const RTA_GATEWAY: u16 = constants::RTA_GATEWAY as u16;
    pub const RTA_PRIORITY: u16 = constants::RTA_PRIORITY as u16;
    pub const RTA_PREFSRC: u16 = constants::RTA_PREFSRC as u16;
    pub const RTA_METRICS: u16 = constants::RTA_METRICS as u16;
    pub const RTA_MULTIPATH: u16 = constants::RTA_MULTIPATH as u16;
    pub const RTA_PROTOINFO: u16 = constants::RTA_PROTOINFO as u16;
    pub const RTA_FLOW: u16 = constants::RTA_FLOW as u16;
    pub const RTA_CACHEINFO: u16 = constants::RTA_CACHEINFO as u16;
    pub const RTA_SESSION: u16 = constants::RTA_SESSION as u16;
    pub const RTA_MP_ALGO: u16 = constants::RTA_MP_ALGO as u16;
    pub const RTA_TABLE: u16 = constants::RTA_TABLE as u16;
    pub const RTA_MARK: u16 = constants::RTA_MARK as u16;
    pub const RTA_MFC_STATS: u16 = constants::RTA_MFC_STATS as u16;
    pub const RTA_VIA: u16 = constants::RTA_VIA as u16;
    pub const RTA_NEWDST: u16 = constants::RTA_NEWDST as u16;
    pub const RTA_PREF: u16 = constants::RTA_PREF as u16;
    pub const RTA_ENCAP_TYPE: u16 = constants::RTA_ENCAP_TYPE as u16;
    pub const RTA_ENCAP: u16 = constants::RTA_ENCAP as u16;
    pub const RTA_EXPIRES: u16 = constants::RTA_EXPIRES as u16;
    pub const RTA_PAD: u16 = constants::RTA_PAD as u16;
    pub const RTA_UID: u16 = constants::RTA_UID as u16;
    pub const RTA_TTL_PROPAGATE: u16 = constants::RTA_TTL_PROPAGATE as u16;

    pub const RTAX_UNSPEC: u16 = constants::RTAX_UNSPEC as u16;
    pub const RTAX_LOCK: u16 = constants::RTAX_LOCK as u16;
    pub const RTAX_MTU: u16 = constants::RTAX_MTU as u16;
    pub const RTAX_WINDOW: u16 = constants::RTAX_WINDOW as u16;
    pub const RTAX_RTT: u16 = constants::RTAX_RTT as u16;
    pub const RTAX_RTTVAR: u16 = constants::RTAX_RTTVAR as u16;
    pub const RTAX_SSTHRESH: u16 = constants::RTAX_SSTHRESH as u16;
    pub const RTAX_CWND: u16 = constants::RTAX_CWND as u16;
    pub const RTAX_ADVMSS: u16 = constants::RTAX_ADVMSS as u16;
    pub const RTAX_REORDERING: u16 = constants::RTAX_REORDERING as u16;
    pub const RTAX_HOPLIMIT: u16 = constants::RTAX_HOPLIMIT as u16;
    pub const RTAX_INITCWND: u16 = constants::RTAX_INITCWND as u16;
    pub const RTAX_FEATURES: u16 = constants::RTAX_FEATURES as u16;
    pub const RTAX_RTO_MIN: u16 = constants::RTAX_RTO_MIN as u16;
    pub const RTAX_INITRWND: u16 = constants::RTAX_INITRWND as u16;
    pub const RTAX_QUICKACK: u16 = constants::RTAX_QUICKACK as u16;
    pub const RTAX_CC_ALGO: u16 = constants::RTAX_CC_ALGO as u16;
    pub const RTAX_FASTOPEN_NO_COOKIE: u16 = constants::RTAX_FASTOPEN_NO_COOKIE as u16;
}

pub use self::rtnl_route_nlas::*;

mod if_states {
	pub const IF_OPER_UNKNOWN: u8 = 0;
	pub const IF_OPER_NOTPRESENT: u8 = 1;
	pub const IF_OPER_DOWN: u8 = 2;
	pub const IF_OPER_LOWERLAYERDOWN: u8 = 3;
	pub const IF_OPER_TESTING: u8 = 4;
	pub const IF_OPER_DORMANT: u8 = 5;
	pub const IF_OPER_UP: u8 = 6;
}
pub use self::if_states::*;
