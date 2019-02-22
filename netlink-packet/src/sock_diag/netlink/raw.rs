#![allow(non_camel_case_types)]

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct netlink_diag_req {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub pad: u16,
    pub ndiag_ino: u32,
    pub ndiag_show: u32,
    pub ndiag_cookie: [u32; 2],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct netlink_diag_msg {
    pub ndiag_family: u8,
    pub ndiag_type: u8,
    pub ndiag_protocol: u8,
    pub ndiag_state: u8,

    pub ndiag_portid: u32,
    pub ndiag_dst_portid: u32,
    pub ndiag_dst_group: u32,
    pub ndiag_ino: u32,
    pub ndiag_cookie: [u32; 2],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct netlink_diag_ring {
    pub ndr_block_size: u32,
    pub ndr_block_nr: u32,
    pub ndr_frame_size: u32,
    pub ndr_frame_nr: u32,
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum attribute {
    // NETLINK_DIAG_NONE, standard nl API requires this attribute!
    NETLINK_DIAG_MEMINFO,
    NETLINK_DIAG_GROUPS,
    NETLINK_DIAG_RX_RING,
    NETLINK_DIAG_TX_RING,
    NETLINK_DIAG_FLAGS,
}

impl attribute {
    pub fn min_value() -> Self {
        attribute::NETLINK_DIAG_MEMINFO
    }

    pub fn max_value() -> Self {
        attribute::NETLINK_DIAG_FLAGS
    }
}

pub const NDIAG_PROTO_ALL: u8 = 0xFF;

pub const NDIAG_SHOW_MEMINFO: u32 = 0x0000_0001; // show memory info of a socket
pub const NDIAG_SHOW_GROUPS: u32 = 0x0000_0002; // show groups of a netlink socket
pub const NDIAG_SHOW_RING_CFG: u32 = 0x0000_0004; // show ring configuration
pub const NDIAG_SHOW_FLAGS: u32 = 0x0000_0008; // show flags of a netlink socket

pub const NDIAG_FLAG_CB_RUNNING: u32 = 0x0000_0001;
pub const NDIAG_FLAG_PKTINFO: u32 = 0x0000_0002;
pub const NDIAG_FLAG_BROADCAST_ERROR: u32 = 0x0000_0004;
pub const NDIAG_FLAG_NO_ENOBUFS: u32 = 0x0000_0008;
pub const NDIAG_FLAG_LISTEN_ALL_NSID: u32 = 0x0000_0010;
pub const NDIAG_FLAG_CAP_ACK: u32 = 0x0000_0020;
pub const NDIAG_FLAG_EXT_ACK: u32 = 0x0000_0040;
pub const NDIAG_FLAG_STRICT_CHK: u32 = 0x0000_0080;
