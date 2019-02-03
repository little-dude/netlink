#![allow(non_camel_case_types)]

use crate::sock_diag::TcpState::*;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct unix_diag_req {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub pad: u16,
    pub udiag_states: u32,
    pub udiag_ino: u32,
    pub udiag_show: u32,
    pub udiag_cookie: [u32; 2],
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum show {
    /// show name (not path)
    UDIAG_SHOW_NAME = 0x0000_0001,
    /// show VFS inode info
    UDIAG_SHOW_VFS = 0x0000_0002,
    /// show peer socket info
    UDIAG_SHOW_PEER = 0x0000_0004,
    /// show pending connections
    UDIAG_SHOW_ICONS = 0x0000_0008,
    /// show skb receive queue len
    UDIAG_SHOW_RQLEN = 0x0000_0010,
    /// show memory info of a socket
    UDIAG_SHOW_MEMINFO = 0x0000_0020,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct unix_diag_msg {
    pub udiag_family: u8,
    pub udiag_type: u8,
    pub udiag_state: u8,
    pub pad: u8,

    pub udiag_ino: u32,
    pub udiag_cookie: [u32; 2],
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum unix_state {
    ESTABLISHED = TCP_ESTABLISHED as u8,
    LISTEN = TCP_LISTEN as u8,
}

impl unix_state {
    pub fn max_value() -> u8 {
        unix_state::LISTEN as u8
    }
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum attribute {
    UNIX_DIAG_NAME,
    UNIX_DIAG_VFS,
    UNIX_DIAG_PEER,
    UNIX_DIAG_ICONS,
    UNIX_DIAG_RQLEN,
    UNIX_DIAG_MEMINFO,
    UNIX_DIAG_SHUTDOWN,
}

impl attribute {
    pub fn max_value() -> u16 {
        attribute::UNIX_DIAG_SHUTDOWN as u16
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct unix_diag_vfs {
    pub udiag_vfs_ino: u32,
    pub udiag_vfs_dev: u32,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct unix_diag_rqlen {
    pub udiag_rqueue: u32,
    pub udiag_wqueue: u32,
}
