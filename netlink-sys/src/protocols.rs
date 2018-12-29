use crate::constants::*;

/// List of netlink protocols
pub enum Protocol {
    /// Receives routing and link updates and may be used to modify the routing tables (both IPv4
    /// and IPv6), IP addresses, link parameters, neighbor setups, queueing disciplines, traffic
    /// classes  and  packet  classifiers  (see rtnetlink(7)).
    Route = NETLINK_ROUTE,
    Unused = NETLINK_UNUSED,
    /// Reserved for user-mode socket protocols.
    UserSock = NETLINK_USERSOCK,
    /// Transport  IPv4  packets  from  netfilter  to  user  space.  Used by ip_queue kernel
    /// module.  After a long period of being declared obsolete (in favor of the more advanced
    /// nfnetlink_queue feature), it was  removed in Linux 3.5.
    Firewall = NETLINK_FIREWALL,
    /// Query information about sockets of various protocol families from the kernel (see sock_diag(7)).
    SockDiag = NETLINK_SOCK_DIAG,
    /// Netfilter/iptables ULOG.
    NfLog = NETLINK_NFLOG,
    /// IPsec.
    Xfrm = NETLINK_XFRM,
    /// SELinux event notifications.
    SELinux = NETLINK_SELINUX,
    /// Open-iSCSI.
    ISCSI = NETLINK_ISCSI,
    /// Auditing.
    Audit = NETLINK_AUDIT,
    /// Access to FIB lookup from user space.
    FibLookup = NETLINK_FIB_LOOKUP,
    /// Kernel connector. See `Documentation/connector/*` in the Linux kernel source tree for further information.
    Connector = NETLINK_CONNECTOR,
    /// Netfilter subsystem.
    Netfilter = NETLINK_NETFILTER,
    /// Transport IPv6 packets from netfilter to user space.  Used by ip6_queue kernel module.
    Ip6Fw = NETLINK_IP6_FW,
    /// DECnet routing messages.
    Decnet = NETLINK_DNRTMSG,
    /// Kernel messages to user space.
    KObjectUevent = NETLINK_KOBJECT_UEVENT,
    ///  Generic netlink family for simplified netlink usage.
    Generic = NETLINK_GENERIC,
    /// SCSI transpots
    ScsiTransport = NETLINK_SCSITRANSPORT,
    ///
    Ecryptfs = NETLINK_ECRYPTFS,
    /// Infiniband RDMA.
    Rdma = NETLINK_RDMA,
    /// Netlink interface to request information about ciphers registered with the kernel crypto
    /// API as well as allow configuration of the kernel crypto API.
    Crypto = NETLINK_CRYPTO,
}
