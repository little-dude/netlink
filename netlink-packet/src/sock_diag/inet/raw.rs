#![allow(non_camel_case_types)]

pub const TCPDIAG_GETSOCK: isize = 18;
pub const DCCPDIAG_GETSOCK: isize = 19;

pub const INET_DIAG_GETSOCK_MAX: isize = 24;

/// Kernel TCP states.
///
/// /include/net/tcp_states.h
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum tcp_state {
    /// (both server and client) represents an open connection, data received can be delivered to the user.
    /// The normal state for the data transfer phase of the connection.
    TCP_ESTABLISHED = 1,
    /// (client) represents waiting for a matching connection request after having sent a connection request.
    TCP_SYN_SENT,
    /// (server) represents waiting for a confirming connection request acknowledgment
    /// after having both received and sent a connection request.
    TCP_SYN_RECV,
    /// (both server and client) represents waiting for a connection termination request from the remote TCP,
    /// or an acknowledgment of the connection termination request previously sent.
    TCP_FIN_WAIT1,
    /// (both server and client) represents waiting for a connection termination request from the remote TCP.
    TCP_FIN_WAIT2,
    /// (either server or client) represents waiting for enough time to pass to be sure
    /// the remote TCP received the acknowledgment of its connection termination request.
    TCP_TIME_WAIT,
    /// (both server and client) represents no connection state at all.
    TCP_CLOSE,
    /// (both server and client) represents waiting for a connection termination request from the local user.
    TCP_CLOSE_WAIT,
    /// (both server and client) represents waiting for an acknowledgment of the connection termination request
    /// previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).
    TCP_LAST_ACK,
    /// (server) represents waiting for a connection request from any remote TCP and port.
    TCP_LISTEN,
    /// (both server and client) represents waiting for a connection termination request acknowledgment from the remote TCP.
    TCP_CLOSING,
}

pub const TCP_STATE_MAX: u8 = tcp_state::TCP_CLOSING as u8;

pub const TCPF_ALL: u32 = 0xFFF;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct tcp_info {
    pub tcpi_state: u8,
    pub tcpi_ca_state: u8,
    pub tcpi_retransmits: u8,
    pub tcpi_probes: u8,
    pub tcpi_backoff: u8,
    pub tcpi_options: u8,
    pub tcpi_wscale: u8,
    pub tcpi_delivery_rate_app_limited: u8,

    pub tcpi_rto: u32,
    pub tcpi_ato: u32,
    pub tcpi_snd_mss: u32,
    pub tcpi_rcv_mss: u32,

    pub tcpi_unacked: u32,
    pub tcpi_sacked: u32,
    pub tcpi_lost: u32,
    pub tcpi_retrans: u32,
    pub tcpi_fackets: u32,

    // Times.
    pub tcpi_last_data_sent: u32,
    pub tcpi_last_ack_sent: u32,
    pub tcpi_last_data_recv: u32,
    pub tcpi_last_ack_recv: u32,

    // Metrics.
    pub tcpi_pmtu: u32,
    pub tcpi_rcv_ssthresh: u32,
    pub tcpi_rtt: u32,
    pub tcpi_rttvar: u32,
    pub tcpi_snd_ssthresh: u32,
    pub tcpi_snd_cwnd: u32,
    pub tcpi_advmss: u32,
    pub tcpi_reordering: u32,

    pub tcpi_rcv_rtt: u32,
    pub tcpi_rcv_space: u32,

    pub tcpi_total_retrans: u32,

    pub tcpi_pacing_rate: u64,
    pub tcpi_max_pacing_rate: u64,
    pub tcpi_bytes_acked: u64,    // RFC4898 tcpEStatsAppHCThruOctetsAcked
    pub tcpi_bytes_received: u64, // RFC4898 tcpEStatsAppHCThruOctetsReceived
    pub tcpi_segs_out: u32,       // RFC4898 tcpEStatsPerfSegsOut
    pub tcpi_segs_in: u32,        // RFC4898 tcpEStatsPerfSegsIn

    pub tcpi_notsent_bytes: u32,
    pub tcpi_min_rtt: u32,
    pub tcpi_data_segs_in: u32,  // RFC4898 tcpEStatsDataSegsIn
    pub tcpi_data_segs_out: u32, // RFC4898 tcpEStatsDataSegsOut

    pub tcpi_delivery_rate: u64,

    pub tcpi_busy_time: u64,      // Time (usec) busy sending data
    pub tcpi_rwnd_limited: u64,   // Time (usec) limited by receive window
    pub tcpi_sndbuf_limited: u64, // Time (usec) limited by send buffer

    pub tcpi_delivered: u32,
    pub tcpi_delivered_ce: u32,

    pub tcpi_bytes_sent: u64,    // RFC4898 tcpEStatsPerfHCDataOctetsOut
    pub tcpi_bytes_retrans: u64, // RFC4898 tcpEStatsPerfOctetsRetrans
    pub tcpi_dsack_dups: u32,    // RFC4898 tcpEStatsStackDSACKDups
    pub tcpi_reord_seen: u32,    // reordering events seen
}

/// Socket identity
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_sockid {
    pub idiag_sport: u16,
    pub idiag_dport: u16,
    pub idiag_src: [u32; 4],
    pub idiag_dst: [u32; 4],
    pub idiag_if: u32,
    pub idiag_cookie: [u32; 2],
}

pub const INET_DIAG_NOCOOKIE: u64 = !0u64;

/// Request structure
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_req {
    pub idiag_family: u8, // Family of addresses.
    pub idiag_src_len: u8,
    pub idiag_dst_len: u8,
    pub idiag_ext: u8, // Query extended information

    pub id: inet_diag_sockid,

    pub idiag_states: u32, // States to dump
    pub idiag_dbs: u32,    // Tables to dump (NI)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_req_v2 {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub idiag_ext: u8,
    pub pad: u8,
    pub idiag_states: u32,
    pub id: inet_diag_sockid,
}

/// SOCK_RAW sockets require the underlied protocol to be
/// additionally specified so we can use @pad member for
/// this, but we can't rename it because userspace programs
/// still may depend on this name. Instead lets use another
/// structure definition as an alias for struct `inet_diag_req_v2`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_req_raw {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub idiag_ext: u8,
    pub sdiag_raw_protocol: u8,
    pub idiag_states: u32,
    pub id: inet_diag_sockid,
}

#[repr(u16)]
pub enum inet_diag_attr {
    INET_DIAG_REQ_NONE,
    INET_DIAG_REQ_BYTECODE,
}
pub const INET_DIAG_REQ_MAX: u16 = inet_diag_attr::INET_DIAG_REQ_BYTECODE as u16;

/// Bytecode is sequence of 4 byte commands followed by variable arguments.
/// All the commands identified by "code" are conditional jumps forward:
/// to offset cc+"yes" or to offset cc+"no". "yes" is supposed to be
/// length of the command and its arguments.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_bc_op {
    pub code: u8,
    pub yes: u8,
    pub no: u16,
}

#[repr(u8)]
pub enum byte_code {
    INET_DIAG_BC_NOP,
    INET_DIAG_BC_JMP,
    INET_DIAG_BC_S_GE,
    INET_DIAG_BC_S_LE,
    INET_DIAG_BC_D_GE,
    INET_DIAG_BC_D_LE,
    INET_DIAG_BC_AUTO,
    INET_DIAG_BC_S_COND,
    INET_DIAG_BC_D_COND,
    INET_DIAG_BC_DEV_COND, // u32 ifindex
    INET_DIAG_BC_MARK_COND,
    INET_DIAG_BC_S_EQ,
    INET_DIAG_BC_D_EQ,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_hostcond {
    pub family: u8,
    pub prefix_len: u8,
    pub port: i32,
    pub addr: [u32; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_markcond {
    pub mark: u32,
    pub mask: u32,
}

/// Base info structure. It contains socket identity (addrs/ports/cookie)
/// and, alas, the information shown by netstat.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_msg {
    pub idiag_family: u8,
    pub idiag_state: u8,
    pub idiag_timer: u8,
    pub idiag_retrans: u8,

    pub id: inet_diag_sockid,

    pub idiag_expires: u32,
    pub idiag_rqueue: u32,
    pub idiag_wqueue: u32,
    pub idiag_uid: u32,
    pub idiag_inode: u32,
}

/// Extensions
#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum extension {
    INET_DIAG_NONE,
    INET_DIAG_MEMINFO,
    INET_DIAG_INFO,
    INET_DIAG_VEGASINFO,
    INET_DIAG_CONG,
    INET_DIAG_TOS,
    INET_DIAG_TCLASS,
    INET_DIAG_SKMEMINFO,
    INET_DIAG_SHUTDOWN,
    INET_DIAG_DCTCPINFO,
    INET_DIAG_PROTOCOL, // response attribute only
    INET_DIAG_SKV6ONLY,
    INET_DIAG_LOCALS,
    INET_DIAG_PEERS,
    INET_DIAG_PAD,
    INET_DIAG_MARK,
    INET_DIAG_BBRINFO,
    INET_DIAG_CLASS_ID,
    INET_DIAG_MD5SIG,

    __INET_DIAG_MAX,
}

pub const INET_DIAG_MAX: u16 = extension::INET_DIAG_MD5SIG as u16 - 1;

/// INET_DIAG_MEM
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct inet_diag_meminfo {
    pub idiag_rmem: u32,
    pub idiag_wmem: u32,
    pub idiag_fmem: u32,
    pub idiag_tmem: u32,
}

/// INET_DIAG_VEGASINFO
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct tcpvegas_info {
    pub tcpv_enabled: u32,
    pub tcpv_rttcnt: u32,
    pub tcpv_rtt: u32,
    pub tcpv_minrtt: u32,
}

/// INET_DIAG_DCTCPINFO
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct tcp_dctcp_info {
    pub dctcp_enabled: u16,
    pub dctcp_ce_state: u16,
    pub dctcp_alpha: u32,
    pub dctcp_ab_ecn: u32,
    pub dctcp_ab_tot: u32,
}

/// INET_DIAG_BBRINFO
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct tcp_bbr_info {
    // u64 bw: max-filtered BW (app throughput) estimate in Byte per sec:
    pub bbr_bw_lo: u32,       // lower 32 bits of bw
    pub bbr_bw_hi: u32,       // upper 32 bits of bw
    pub bbr_min_rtt: u32,     // min-filtered RTT in uSec
    pub bbr_pacing_gain: u32, // pacing gain shifted left 8 bits
    pub bbr_cwnd_gain: u32,   // cwnd gain shifted left 8 bits
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union tcp_cc_info {
    pub vegas: tcpvegas_info,
    pub dctcp: tcp_dctcp_info,
    pub bbr: tcp_bbr_info,
}
