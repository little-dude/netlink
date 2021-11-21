// SPDX-License-Identifier: MIT

pub use netlink_packet_core::constants::*;

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;

pub const AF_UNSPEC: u8 = libc::AF_UNSPEC as u8;
pub const AF_UNIX: u8 = libc::AF_UNIX as u8;
// pub const AF_LOCAL: u8 = libc::AF_LOCAL as u8;
pub const AF_INET: u8 = libc::AF_INET as u8;
pub const AF_AX25: u8 = libc::AF_AX25 as u8;
pub const AF_IPX: u8 = libc::AF_IPX as u8;
pub const AF_APPLETALK: u8 = libc::AF_APPLETALK as u8;
pub const AF_NETROM: u8 = libc::AF_NETROM as u8;
pub const AF_BRIDGE: u8 = libc::AF_BRIDGE as u8;
pub const AF_ATMPVC: u8 = libc::AF_ATMPVC as u8;
pub const AF_X25: u8 = libc::AF_X25 as u8;
pub const AF_INET6: u8 = libc::AF_INET6 as u8;
pub const AF_ROSE: u8 = libc::AF_ROSE as u8;
pub const AF_DECNET: u8 = libc::AF_DECnet as u8;
pub const AF_NETBEUI: u8 = libc::AF_NETBEUI as u8;
pub const AF_SECURITY: u8 = libc::AF_SECURITY as u8;
pub const AF_KEY: u8 = libc::AF_KEY as u8;
pub const AF_NETLINK: u8 = libc::AF_NETLINK as u8;
// pub const AF_ROUTE: u8 = libc::AF_ROUTE as u8;
pub const AF_PACKET: u8 = libc::AF_PACKET as u8;
pub const AF_ASH: u8 = libc::AF_ASH as u8;
pub const AF_ECONET: u8 = libc::AF_ECONET as u8;
pub const AF_ATMSVC: u8 = libc::AF_ATMSVC as u8;
pub const AF_RDS: u8 = libc::AF_RDS as u8;
pub const AF_SNA: u8 = libc::AF_SNA as u8;
pub const AF_IRDA: u8 = libc::AF_IRDA as u8;
pub const AF_PPPOX: u8 = libc::AF_PPPOX as u8;
pub const AF_WANPIPE: u8 = libc::AF_WANPIPE as u8;
pub const AF_LLC: u8 = libc::AF_LLC as u8;
pub const AF_CAN: u8 = libc::AF_CAN as u8;
pub const AF_TIPC: u8 = libc::AF_TIPC as u8;
pub const AF_BLUETOOTH: u8 = libc::AF_BLUETOOTH as u8;
pub const AF_IUCV: u8 = libc::AF_IUCV as u8;
pub const AF_RXRPC: u8 = libc::AF_RXRPC as u8;
pub const AF_ISDN: u8 = libc::AF_ISDN as u8;
pub const AF_PHONET: u8 = libc::AF_PHONET as u8;
pub const AF_IEEE802154: u8 = libc::AF_IEEE802154 as u8;
pub const AF_CAIF: u8 = libc::AF_CAIF as u8;
pub const AF_ALG: u8 = libc::AF_ALG as u8;

/// Dummy protocol for TCP
pub const IPPROTO_IP: u8 = 0;
/// Internet Control Message Protocol
pub const IPPROTO_ICMP: u8 = 1;
/// Internet Group Management Protocol
pub const IPPROTO_IGMP: u8 = 2;
/// IPIP tunnels (older KA9Q tunnels use 94)
pub const IPPROTO_IPIP: u8 = 4;
/// Transmission Control Protocol
pub const IPPROTO_TCP: u8 = 6;
/// Exterior Gateway Protocol
pub const IPPROTO_EGP: u8 = 8;
/// PUP protocol
pub const IPPROTO_PUP: u8 = 12;
/// User Datagram Protocol
pub const IPPROTO_UDP: u8 = 17;
/// XNS IDP protocol
pub const IPPROTO_IDP: u8 = 22;
/// SO Transport Protocol Class 4
pub const IPPROTO_TP: u8 = 29;
/// Datagram Congestion Control Protocol
pub const IPPROTO_DCCP: u8 = 33;
/// IPv6 header
pub const IPPROTO_IPV6: u8 = 41;
/// Reservation Protocol
pub const IPPROTO_RSVP: u8 = 46;
/// General Routing Encapsulation
pub const IPPROTO_GRE: u8 = 47;
/// encapsulating security payload
pub const IPPROTO_ESP: u8 = 50;
/// authentication header
pub const IPPROTO_AH: u8 = 51;
/// Multicast Transport Protocol
pub const IPPROTO_MTP: u8 = 92;
/// IP option pseudo header for BEET
pub const IPPROTO_BEETPH: u8 = 94;
/// Encapsulation Header
pub const IPPROTO_ENCAP: u8 = 98;
/// Protocol Independent Multicast
pub const IPPROTO_PIM: u8 = 103;
/// Compression Header Protocol
pub const IPPROTO_COMP: u8 = 108;
/// Stream Control Transmission Protocol
pub const IPPROTO_SCTP: u8 = 132;
/// UDP-Lite protocol
pub const IPPROTO_UDPLITE: u8 = 136;
/// MPLS in IP
pub const IPPROTO_MPLS: u8 = 137;
/// Raw IP packets
pub const IPPROTO_RAW: u8 = 255;
/// IPv6 Hop-by-Hop options
pub const IPPROTO_HOPOPTS: u8 = 0;
/// IPv6 routing header
pub const IPPROTO_ROUTING: u8 = 43;
/// IPv6 fragmentation header
pub const IPPROTO_FRAGMENT: u8 = 44;
/// ICMPv6
pub const IPPROTO_ICMPV6: u8 = 58;
/// IPv6 no next header
pub const IPPROTO_NONE: u8 = 59;
/// IPv6 destination options
pub const IPPROTO_DSTOPTS: u8 = 60;
/// IPv6 mobility header
pub const IPPROTO_MH: u8 = 135;

// Extensions for inet
pub const INET_DIAG_NONE: u16 = 0;
pub const INET_DIAG_MEMINFO: u16 = 1;
pub const INET_DIAG_INFO: u16 = 2;
pub const INET_DIAG_VEGASINFO: u16 = 3;
pub const INET_DIAG_CONG: u16 = 4;
pub const INET_DIAG_TOS: u16 = 5;
pub const INET_DIAG_TCLASS: u16 = 6;
pub const INET_DIAG_SKMEMINFO: u16 = 7;
pub const INET_DIAG_SHUTDOWN: u16 = 8;

pub const INET_DIAG_DCTCPINFO: u16 = 9;
pub const INET_DIAG_PROTOCOL: u16 = 10;
pub const INET_DIAG_SKV6ONLY: u16 = 11;
pub const INET_DIAG_LOCALS: u16 = 12;
pub const INET_DIAG_PEERS: u16 = 13;
pub const INET_DIAG_PAD: u16 = 14;
pub const INET_DIAG_MARK: u16 = 15;
pub const INET_DIAG_BBRINFO: u16 = 16;
pub const INET_DIAG_CLASS_ID: u16 = 17;
pub const INET_DIAG_MD5SIG: u16 = 18;

/// (both server and client) represents an open connection, data
/// received can be delivered to the user. The normal state for the
/// data transfer phase of the connection.
pub const TCP_ESTABLISHED: u8 = 1;
/// (client) represents waiting for a matching connection request
/// after having sent a connection request.
pub const TCP_SYN_SENT: u8 = 2;
/// (server) represents waiting for a confirming connection request
/// acknowledgment after having both received and sent a connection
/// request.
pub const TCP_SYN_RECV: u8 = 3;
/// (both server and client) represents waiting for a connection
/// termination request from the remote TCP, or an acknowledgment of
/// the connection termination request previously sent.
pub const TCP_FIN_WAIT1: u8 = 4;
/// (both server and client) represents waiting for a connection
/// termination request from the remote TCP.
pub const TCP_FIN_WAIT2: u8 = 5;
/// (either server or client) represents waiting for enough time to
/// pass to be sure the remote TCP received the acknowledgment of its
/// connection termination request.
pub const TCP_TIME_WAIT: u8 = 6;
/// (both server and client) represents no connection state at all.
pub const TCP_CLOSE: u8 = 7;
/// (both server and client) represents waiting for a connection
/// termination request from the local user.
pub const TCP_CLOSE_WAIT: u8 = 8;
/// (both server and client) represents waiting for an acknowledgment
/// of the connection termination request previously sent to the
/// remote TCP (which includes an acknowledgment of its connection
/// termination request).
pub const TCP_LAST_ACK: u8 = 9;
/// (server) represents waiting for a connection request from any
/// remote TCP and port.
pub const TCP_LISTEN: u8 = 10;
/// (both server and client) represents waiting for a connection termination request acknowledgment from the remote TCP.
pub const TCP_CLOSING: u8 = 11;

/// The attribute reported in answer to this request is
/// `UNIX_DIAG_NAME`. The payload associated with this attribute is
/// the pathname to which the socket was bound (a se quence of bytes
/// up to `UNIX_PATH_MAX` length).
pub const UDIAG_SHOW_NAME: u32 = 1 << UNIX_DIAG_NAME;
/// The attribute reported in answer to this request is
/// `UNIX_DIAG_VFS`, which returns VFS information associated to the
/// inode.
pub const UDIAG_SHOW_VFS: u32 = 1 << UNIX_DIAG_VFS;
/// The attribute reported in answer to this request is
/// `UNIX_DIAG_PEER`, which carries the peer's inode number. This
/// attribute is reported for connected sockets only.
pub const UDIAG_SHOW_PEER: u32 = 1 << UNIX_DIAG_PEER;
/// The attribute reported in answer to this request is
/// `UNIX_DIAG_ICONS`, which information about pending
/// connections. Specifically, it contains the inode numbers of the
/// sockets that have passed the `connect(2)` call, but hasn't been
/// processed with `accept(2) yet`. This attribute is reported for
/// listening sockets only.
pub const UDIAG_SHOW_ICONS: u32 = 1 << UNIX_DIAG_ICONS;
/// The attribute reported in answer to this request is
/// `UNIX_DIAG_RQLEN`, which reports:
///
/// - for listening socket: the number of pending connections, and the
///   backlog length (which equals to the value passed as the second
///   argument to `listen(2)`).
/// - for established sockets: the amount of data in incoming queue,
///   and the amount of memory available for sending
pub const UDIAG_SHOW_RQLEN: u32 = 1 << UNIX_DIAG_RQLEN;
/// The attribute reported in answer to this request is
/// `UNIX_DIAG_MEMINFO` which shows memory information about the
/// socket
pub const UDIAG_SHOW_MEMINFO: u32 = 1 << UNIX_DIAG_MEMINFO;

pub const UNIX_DIAG_NAME: u16 = 0;
pub const UNIX_DIAG_VFS: u16 = 1;
pub const UNIX_DIAG_PEER: u16 = 2;
pub const UNIX_DIAG_ICONS: u16 = 3;
pub const UNIX_DIAG_RQLEN: u16 = 4;
pub const UNIX_DIAG_MEMINFO: u16 = 5;
pub const UNIX_DIAG_SHUTDOWN: u16 = 6;

/// Provides sequenced, reliable, two-way, connection-based byte
/// streams. An out-of-band data transmission mechanism may be
/// supported.
pub const SOCK_STREAM: u8 = libc::SOCK_STREAM as u8;
/// Supports datagrams (connectionless, unreliable messages of a fixed
/// maximum length).
pub const SOCK_DGRAM: u8 = libc::SOCK_DGRAM as u8;
/// Provides a sequenced, reliable, two-way connection-based data
/// transmission path for datagrams of fixed maximum length; a
/// consumer is required to read an entire packet with each input
/// system call.
pub const SOCK_SEQPACKET: u8 = libc::SOCK_SEQPACKET as u8;
/// Provides raw network protocol access.
pub const SOCK_RAW: u8 = libc::SOCK_RAW as u8;
/// Provides a reliable datagram layer that does not guarantee
/// ordering.
pub const SOCK_RDM: u8 = libc::SOCK_RDM as u8;
/// Obsolete and should not be used in new programs; see `packet(7)`.
pub const SOCK_PACKET: u8 = libc::SOCK_PACKET as u8;

/// Nothing bad has been observed recently. No apparent reordering, packet loss, or ECN marks.
pub const TCP_CA_OPEN: u8 = 0;
pub const TCPF_CA_OPEN: u32 = 1 << TCP_CA_OPEN;

/// The sender enters disordered state when it has received DUPACKs or
/// SACKs in the last round of packets sent. This could be due to
/// packet loss or reordering but needs further information to confirm
/// packets have been lost.
pub const TCP_CA_DISORDER: u8 = 1;
pub const TCPF_CA_DISORDER: u32 = 1 << TCP_CA_DISORDER;
/// The sender enters Congestion Window Reduction (CWR) state when it
/// has received ACKs with ECN-ECE marks, or has experienced
/// congestion or packet discard on the sender host (e.g. qdisc).
pub const TCP_CA_CWR: u8 = 2;
pub const TCPF_CA_CWR: u32 = 1 << TCP_CA_CWR;
/// The sender is in fast recovery and retransmitting lost packets, typically triggered by ACK events.
pub const TCP_CA_RECOVERY: u8 = 3;
pub const TCPF_CA_RECOVERY: u32 = 1 << TCP_CA_RECOVERY;
/// The sender is in loss recovery triggered by retransmission timeout.
pub const TCP_CA_LOSS: u8 = 4;
pub const TCPF_CA_LOSS: u32 = 1 << TCP_CA_LOSS;

pub const TCPI_OPT_TIMESTAMPS: u8 = 1;
pub const TCPI_OPT_SACK: u8 = 2;
pub const TCPI_OPT_WSCALE: u8 = 4;
/// ECN was negociated at TCP session init
pub const TCPI_OPT_ECN: u8 = 8;
/// We received at least one packet with ECT
pub const TCPI_OPT_ECN_SEEN: u8 = 16;
/// SYN-ACK acked data in SYN sent or rcvd
pub const TCPI_OPT_SYN_DATA: u8 = 32;

/// Shutdown state of a socket. A socket shut down with `SHUT_RD` can
/// no longer receive data. See also `man 2 shutdown`.
pub const SHUT_RD: u8 = 0;
/// Shutdown state of a socket. A socket shut down with `SHUT_WR` can
/// no longer send data. See also `man 2 shutdown`.
pub const SHUT_WR: u8 = 1;
/// Shutdown state of a socket. A socket shut down with `SHUT_RDWR`
/// can no longer receive nor send data. See also `man 2 shutdown`.
pub const SHUT_RDWR: u8 = 2;
