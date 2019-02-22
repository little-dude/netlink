#![allow(non_camel_case_types)]

use libc::MAX_ADDR_LEN;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct packet_diag_req {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub pad: u16,
    pub pdiag_ino: u32,
    pub pdiag_show: u32,
    pub pdiag_cookie: [u32; 2],
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum show {
    /// Basic packet_sk information
    PACKET_SHOW_INFO = 0x0000_0001,
    /// A set of packet_diag_mclist-s
    PACKET_SHOW_MCLIST = 0x0000_0002,
    /// Rings configuration parameters
    PACKET_SHOW_RING_CFG = 0x0000_0004,
    PACKET_SHOW_FANOUT = 0x0000_0008,
    PACKET_SHOW_MEMINFO = 0x0000_0010,
    PACKET_SHOW_FILTER = 0x0000_0020,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct packet_diag_msg {
    pub pdiag_family: u8,
    pub pdiag_type: u8,
    pub pdiag_num: u16,
    pub pdiag_ino: u32,
    pub pdiag_cookie: [u32; 2],
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum attribute {
    // PACKET_DIAG_NONE, standard nl API requires this attribute!
    PACKET_DIAG_INFO,
    PACKET_DIAG_MCLIST,
    PACKET_DIAG_RX_RING,
    PACKET_DIAG_TX_RING,
    PACKET_DIAG_FANOUT,
    PACKET_DIAG_UID,
    PACKET_DIAG_MEMINFO,
    PACKET_DIAG_FILTER,
}

impl attribute {
    pub fn max_value() -> u16 {
        attribute::PACKET_DIAG_FILTER as u16
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct packet_diag_info {
    pub pdi_index: u32,
    pub pdi_version: u32,
    pub pdi_reserve: u32,
    pub pdi_copy_thresh: u32,
    pub pdi_tstamp: u32,
    pub pdi_flags: u32,
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum info_flag {
    PDI_RUNNING = 0x1,
    PDI_AUXDATA = 0x2,
    PDI_ORIGDEV = 0x4,
    PDI_VNETHDR = 0x8,
    PDI_LOSS = 0x10,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct packet_diag_mclist {
    pub pdmc_index: u32,
    pub pdmc_count: u32,
    pub pdmc_type: u16,
    pub pdmc_alen: u16,
    pub pdmc_addr: [u8; MAX_ADDR_LEN],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct packet_diag_ring {
    pub pdr_block_size: u32,
    pub pdr_block_nr: u32,
    pub pdr_frame_size: u32,
    pub pdr_frame_nr: u32,
    pub pdr_retire_tmo: u32,
    pub pdr_sizeof_priv: u32,
    pub pdr_features: u32,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum packet_type {
    PACKET_HOST,      // To us
    PACKET_BROADCAST, // To all
    PACKET_MULTICAST, // To group
    PACKET_OTHERHOST, // To someone else
    PACKET_OUTGOING,  // Outgoing of any type
    PACKET_LOOPBACK,  // MC/BRD frame looped back
    PACKET_USER,      // To user space
    PACKET_KERNEL,    // To kernel space
    // Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space
    PACKET_FASTROUTE, // Fastrouted frame
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum fanout_type {
    PACKET_FANOUT_HASH,
    PACKET_FANOUT_LB,
    PACKET_FANOUT_CPU,
    PACKET_FANOUT_ROLLOVER,
    PACKET_FANOUT_RND,
    PACKET_FANOUT_QM,
    PACKET_FANOUT_CBPF,
    PACKET_FANOUT_EBPF,
}

pub const PACKET_FANOUT_FLAG_ROLLOVER: u16 = 0x1000;
pub const PACKET_FANOUT_FLAG_UNIQUEID: u16 = 0x2000;
pub const PACKET_FANOUT_FLAG_DEFRAG: u16 = 0x8000;
