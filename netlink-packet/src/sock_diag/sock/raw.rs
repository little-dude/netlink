#![allow(non_camel_case_types)]

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct sock_diag_req {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
}

pub enum sk_meminfo_vars {
    SK_MEMINFO_RMEM_ALLOC,
    SK_MEMINFO_RCVBUF,
    SK_MEMINFO_WMEM_ALLOC,
    SK_MEMINFO_SNDBUF,
    SK_MEMINFO_FWD_ALLOC,
    SK_MEMINFO_WMEM_QUEUED,
    SK_MEMINFO_OPTMEM,
    SK_MEMINFO_BACKLOG,
    SK_MEMINFO_DROPS,

    SK_MEMINFO_VARS,
}

/// Socket memory information
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct sk_meminfo {
    /// The amount of data in receive queue.
    pub rmem_alloc: u32,
    /// The receive socket buffer as set by SO_RCVBUF.
    pub recvbuf: u32,
    /// The amount of data in send queue.
    pub wmem_alloc: u32,
    /// The send socket buffer as set by SO_SNDBUF.
    pub sndbuf: u32,
    /// The amount of memory scheduled for future use (TCP only).
    pub fwd_alloc: u32,
    /// The amount of data queued by TCP, but not yet sent.
    pub wmem_queued: u32,
    /// The amount of memory allocated for the socket's service needs (e.g., socket filter).
    pub optmem: u32,
    /// The amount of packets in the backlog (not yet processed).
    pub backlog: u32,
    /// The amount of packets was dropped.
    pub drops: u32,
}

#[repr(u16)]
pub enum sknetlink_groups {
    SKNLGRP_NONE,
    SKNLGRP_INET_TCP_DESTROY,
    SKNLGRP_INET_UDP_DESTROY,
    SKNLGRP_INET6_TCP_DESTROY,
    SKNLGRP_INET6_UDP_DESTROY,
}
