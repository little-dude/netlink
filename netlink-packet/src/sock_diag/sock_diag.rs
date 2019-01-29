#![allow(non_camel_case_types)]

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;

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

#[repr(u16)]
pub enum sknetlink_groups {
    SKNLGRP_NONE,
    SKNLGRP_INET_TCP_DESTROY,
    SKNLGRP_INET_UDP_DESTROY,
    SKNLGRP_INET6_TCP_DESTROY,
    SKNLGRP_INET6_UDP_DESTROY,
}
