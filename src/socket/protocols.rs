use super::constants;

/// List of netlink protocols
pub enum Protocol {
    /// Receives routing and link updates and may be used to modify the routing tables (both IPv4
    /// and IPv6), IP addresses, link parameters, neighbor setups, queueing disciplines, traffic
    /// classes  and  packet  classifiers  (see rtnetlink(7)).
    Route = constants::NETLINK_ROUTE as isize,
    Unused = constants::NETLINK_UNUSED as isize,
    /// Reserved for user-mode socket protocols.
    UserSock = constants::NETLINK_USERSOCK as isize,
    /// Transport  IPv4  packets  from  netfilter  to  user  space.  Used by ip_queue kernel
    /// module.  After a long period of being declared obsolete (in favor of the more advanced
    /// nfnetlink_queue feature), it was  removed in Linux 3.5.
    Firewall = constants::NETLINK_FIREWALL as isize,
    /// Query information about sockets of various protocol families from the kernel (see sock_diag(7)).
    SockDiag = constants::NETLINK_SOCK_DIAG as isize,
    /// Netfilter/iptables ULOG.
    NfLog = constants::NETLINK_NFLOG as isize,
    /// IPsec.
    Xfrm = constants::NETLINK_XFRM as isize,
    /// SELinux event notifications.
    SELinux = constants::NETLINK_SELINUX as isize,
    /// Open-iSCSI.
    ISCSI = constants::NETLINK_ISCSI as isize,
    /// Auditing.
    Audit = constants::NETLINK_AUDIT as isize,
    /// Access to FIB lookup from user space.
    FibLookup = constants::NETLINK_FIB_LOOKUP as isize,
    /// Kernel connector. See `Documentation/connector/*` in the Linux kernel source tree for further information.
    Connector = constants::NETLINK_CONNECTOR as isize,
    /// Netfilter subsystem.
    Netfilter = constants::NETLINK_NETFILTER as isize,
    /// Transport IPv6 packets from netfilter to user space.  Used by ip6_queue kernel module.
    Ip6Fw = constants::NETLINK_IP6_FW as isize,
    /// DECnet routing messages.
    Decnet = constants::NETLINK_DNRTMSG as isize,
    /// Kernel messages to user space.
    KObjectUevent = constants::NETLINK_KOBJECT_UEVENT as isize,
    ///  Generic netlink family for simplified netlink usage.
    Generic = constants::NETLINK_GENERIC as isize,
    /// SCSI transpots
    ScsiTransport = constants::NETLINK_SCSITRANSPORT as isize,
    ///
    Ecryptfs = constants::NETLINK_ECRYPTFS as isize,
    /// Infiniband RDMA.
    Rdma = constants::NETLINK_RDMA as isize,
    /// Netlink interface to request information about ciphers registered with the kernel crypto
    /// API as well as allow configuration of the kernel crypto API.
    Crypto = constants::NETLINK_CRYPTO as isize,
}
