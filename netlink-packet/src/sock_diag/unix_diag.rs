#![allow(non_camel_case_types)]

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
pub enum unix_diag_show {
    UDIAG_SHOW_NAME = 0x00000001,    /* show name (not path) */
    UDIAG_SHOW_VFS = 0x00000002,     /* show VFS inode info */
    UDIAG_SHOW_PEER = 0x00000004,    /* show peer socket info */
    UDIAG_SHOW_ICONS = 0x00000008,   /* show pending connections */
    UDIAG_SHOW_RQLEN = 0x00000010,   /* show skb receive queue len */
    UDIAG_SHOW_MEMINFO = 0x00000020, /* show memory info of a socket */
}

struct unix_diag_msg {
    pub udiag_family: u8,
    pub udiag_type: u8,
    pub udiag_state: u8,
    pub pad: u8,

    pub udiag_ino: u32,
    pub udiag_cookie: [u32; 2],
}

#[repr(u16)]
pub enum unix_diag_attribute {
    /* UNIX_DIAG_NONE, standard nl API requires this attribute!  */
    UNIX_DIAG_NAME,
    UNIX_DIAG_VFS,
    UNIX_DIAG_PEER,
    UNIX_DIAG_ICONS,
    UNIX_DIAG_RQLEN,
    UNIX_DIAG_MEMINFO,
    UNIX_DIAG_SHUTDOWN,

    __UNIX_DIAG_MAX,
}

pub const UNIX_DIAG_MAX: u16 = unix_diag_attribute::__UNIX_DIAG_MAX as u16 - 1;

pub struct unix_diag_vfs {
    pub udiag_vfs_ino: u32,
    pub udiag_vfs_dev: u32,
}

pub struct unix_diag_rqlen {
    pub udiag_rqueue: u32,
    pub udiag_wqueue: u32,
}
