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
    use libc;
    use bindgen_constants as constants;
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
    use libc;
    use bindgen_constants as constants;

    pub const AF_UNSPEC: u16 = libc::AF_UNSPEC as u16;
    pub const AF_UNIX: u16 = libc::AF_UNIX as u16;
    pub const AF_INET: u16 = libc::AF_INET as u16;
    pub const AF_AX25: u16 = libc::AF_AX25 as u16;
    pub const AF_IPX: u16 = libc::AF_IPX as u16;
    pub const AF_APPLETALK: u16 = libc::AF_APPLETALK as u16;
    pub const AF_NETROM: u16 = libc::AF_NETROM as u16;
    pub const AF_BRIDGE: u16 = libc::AF_BRIDGE as u16;
    pub const AF_ATMPVC: u16 = libc::AF_ATMPVC as u16;
    pub const AF_X25: u16 = libc::AF_X25 as u16;
    pub const AF_INET6: u16 = libc::AF_INET6 as u16;

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
