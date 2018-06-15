use constants;

/// List of netlink protocols
pub enum Protocol {
    /// Receives routing and link updates and may be used to modify the routing tables (both IPv4
    /// and IPv6), IP addresses, link parameters, neighbor setups, queueing disciplines, traffic
    /// classes  and  packet  classifiers  (see rtnetlink(7)).
    Route = constants::NETLINK_ROUTE,
    Unused = constants::NETLINK_UNUSED,
    /// Reserved for user-mode socket protocols.
    UserSock = constants::NETLINK_USERSOCK,
    /// Transport  IPv4  packets  from  netfilter  to  user  space.  Used by ip_queue kernel
    /// module.  After a long period of being declared obsolete (in favor of the more advanced
    /// nfnetlink_queue feature), it was  removed in Linux 3.5.
    Firewall = constants::NETLINK_FIREWALL,
    /// Query information about sockets of various protocol families from the kernel (see sock_diag(7)).
    SockDiag = constants::NETLINK_SOCK_DIAG,
    /// Netfilter/iptables ULOG.
    NfLog = constants::NETLINK_NFLOG,
    /// IPsec.
    Xfrm = constants::NETLINK_XFRM,
    /// SELinux event notifications.
    SELinux = constants::NETLINK_SELINUX,
    /// Open-iSCSI.
    ISCSI = constants::NETLINK_ISCSI,
    /// Auditing.
    Audit = constants::NETLINK_AUDIT,
    /// Access to FIB lookup from user space.
    FibLookup = constants::NETLINK_FIB_LOOKUP,
    /// Kernel connector. See `Documentation/connector/*` in the Linux kernel source tree for further information.
    Connector = constants::NETLINK_CONNECTOR,
    /// Netfilter subsystem.
    Netfilter = constants::NETLINK_NETFILTER,
    /// Transport IPv6 packets from netfilter to user space.  Used by ip6_queue kernel module.
    Ip6Fw = constants::NETLINK_IP6_FW,
    /// DECnet routing messages.
    Decnet = constants::NETLINK_DNRTMSG,
    /// Kernel messages to user space.
    KObjectUevent = constants::NETLINK_KOBJECT_UEVENT,
    ///  Generic netlink family for simplified netlink usage.
    Generic = constants::NETLINK_GENERIC,
    /// SCSI transpots
    ScsiTransport = constants::NETLINK_SCSITRANSPORT,
    ///
    Ecryptfs = constants::NETLINK_ECRYPTFS,
    /// Infiniband RDMA.
    Rdma = constants::NETLINK_RDMA,
    /// Netlink interface to request information about ciphers registered with the kernel crypto
    /// API as well as allow configuration of the kernel crypto API.
    Crypto = constants::NETLINK_CRYPTO,
}
