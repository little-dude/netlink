//! Define constants related to generic netlink
pub const GENL_ID_CTRL: u16 = libc::GENL_ID_CTRL as u16;
pub const GENL_HDRLEN: usize = 4;

pub const CTRL_CMD_UNSPEC: u8 = libc::CTRL_CMD_UNSPEC as u8;
pub const CTRL_CMD_NEWFAMILY: u8 = libc::CTRL_CMD_NEWFAMILY as u8;
pub const CTRL_CMD_DELFAMILY: u8 = libc::CTRL_CMD_DELFAMILY as u8;
pub const CTRL_CMD_GETFAMILY: u8 = libc::CTRL_CMD_GETFAMILY as u8;
pub const CTRL_CMD_NEWOPS: u8 = libc::CTRL_CMD_NEWOPS as u8;
pub const CTRL_CMD_DELOPS: u8 = libc::CTRL_CMD_DELOPS as u8;
pub const CTRL_CMD_GETOPS: u8 = libc::CTRL_CMD_GETOPS as u8;
pub const CTRL_CMD_NEWMCAST_GRP: u8 = libc::CTRL_CMD_NEWMCAST_GRP as u8;
pub const CTRL_CMD_DELMCAST_GRP: u8 = libc::CTRL_CMD_DELMCAST_GRP as u8;
pub const CTRL_CMD_GETMCAST_GRP: u8 = libc::CTRL_CMD_GETMCAST_GRP as u8;
pub const CTRL_CMD_GETPOLICY: u8 = 10;

pub const CTRL_ATTR_UNSPEC: u16 = libc::CTRL_ATTR_UNSPEC as u16;
pub const CTRL_ATTR_FAMILY_ID: u16 = libc::CTRL_ATTR_FAMILY_ID as u16;
pub const CTRL_ATTR_FAMILY_NAME: u16 = libc::CTRL_ATTR_FAMILY_NAME as u16;
pub const CTRL_ATTR_VERSION: u16 = libc::CTRL_ATTR_VERSION as u16;
pub const CTRL_ATTR_HDRSIZE: u16 = libc::CTRL_ATTR_HDRSIZE as u16;
pub const CTRL_ATTR_MAXATTR: u16 = libc::CTRL_ATTR_MAXATTR as u16;
pub const CTRL_ATTR_OPS: u16 = libc::CTRL_ATTR_OPS as u16;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = libc::CTRL_ATTR_MCAST_GROUPS as u16;
pub const CTRL_ATTR_POLICY: u16 = 8;
pub const CTRL_ATTR_OP_POLICY: u16 = 9;
pub const CTRL_ATTR_OP: u16 = 10;

pub const CTRL_ATTR_OP_UNSPEC: u16 = libc::CTRL_ATTR_OP_UNSPEC as u16;
pub const CTRL_ATTR_OP_ID: u16 = libc::CTRL_ATTR_OP_ID as u16;
pub const CTRL_ATTR_OP_FLAGS: u16 = libc::CTRL_ATTR_OP_FLAGS as u16;

pub const CTRL_ATTR_MCAST_GRP_UNSPEC: u16 = libc::CTRL_ATTR_MCAST_GRP_UNSPEC as u16;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = libc::CTRL_ATTR_MCAST_GRP_NAME as u16;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = libc::CTRL_ATTR_MCAST_GRP_ID as u16;

pub const CTRL_ATTR_POLICY_UNSPEC: u16 = 0;
pub const CTRL_ATTR_POLICY_DO: u16 = 1;
pub const CTRL_ATTR_POLICY_DUMP: u16 = 2;
