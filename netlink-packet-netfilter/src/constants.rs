// SPDX-License-Identifier: MIT

pub use netlink_packet_core::constants::*;

pub const AF_UNSPEC: u8 = libc::AF_UNSPEC as u8;
pub const AF_UNIX: u8 = libc::AF_UNIX as u8;
pub const AF_LOCAL: u8 = libc::AF_LOCAL as u8;
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
pub const AF_ROUTE: u8 = libc::AF_ROUTE as u8;
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

pub const NFNETLINK_V0: u8 = libc::NFNETLINK_V0 as u8;

pub const NFNL_SUBSYS_NONE: u8 = libc::NFNL_SUBSYS_NONE as u8;
pub const NFNL_SUBSYS_CTNETLINK: u8 = libc::NFNL_SUBSYS_CTNETLINK as u8;
pub const NFNL_SUBSYS_CTNETLINK_EXP: u8 = libc::NFNL_SUBSYS_CTNETLINK_EXP as u8;
pub const NFNL_SUBSYS_QUEUE: u8 = libc::NFNL_SUBSYS_QUEUE as u8;
pub const NFNL_SUBSYS_ULOG: u8 = libc::NFNL_SUBSYS_ULOG as u8;
pub const NFNL_SUBSYS_OSF: u8 = libc::NFNL_SUBSYS_OSF as u8;
pub const NFNL_SUBSYS_IPSET: u8 = libc::NFNL_SUBSYS_IPSET as u8;
pub const NFNL_SUBSYS_ACCT: u8 = libc::NFNL_SUBSYS_ACCT as u8;
pub const NFNL_SUBSYS_CTNETLINK_TIMEOUT: u8 = libc::NFNL_SUBSYS_CTNETLINK_TIMEOUT as u8;
pub const NFNL_SUBSYS_CTHELPER: u8 = libc::NFNL_SUBSYS_CTHELPER as u8;
pub const NFNL_SUBSYS_NFTABLES: u8 = libc::NFNL_SUBSYS_NFTABLES as u8;
pub const NFNL_SUBSYS_NFT_COMPAT: u8 = libc::NFNL_SUBSYS_NFT_COMPAT as u8;

pub const NFULA_CFG_CMD: u16 = libc::NFULA_CFG_CMD as u16;
pub const NFULA_CFG_MODE: u16 = libc::NFULA_CFG_MODE as u16;
pub const NFULA_CFG_NLBUFSIZ: u16 = libc::NFULA_CFG_NLBUFSIZ as u16;
pub const NFULA_CFG_TIMEOUT: u16 = libc::NFULA_CFG_TIMEOUT as u16;
pub const NFULA_CFG_QTHRESH: u16 = libc::NFULA_CFG_QTHRESH as u16;
pub const NFULA_CFG_FLAGS: u16 = libc::NFULA_CFG_FLAGS as u16;
pub const NLBUFSIZ_MAX: u32 = 131072;

pub const NFULA_PACKET_HDR: u16 = libc::NFULA_PACKET_HDR as u16;
pub const NFULA_MARK: u16 = libc::NFULA_MARK as u16;
pub const NFULA_TIMESTAMP: u16 = libc::NFULA_TIMESTAMP as u16;
pub const NFULA_IFINDEX_INDEV: u16 = libc::NFULA_IFINDEX_INDEV as u16;
pub const NFULA_IFINDEX_OUTDEV: u16 = libc::NFULA_IFINDEX_OUTDEV as u16;
pub const NFULA_IFINDEX_PHYSINDEV: u16 = libc::NFULA_IFINDEX_PHYSINDEV as u16;
pub const NFULA_IFINDEX_PHYSOUTDEV: u16 = libc::NFULA_IFINDEX_PHYSOUTDEV as u16;
pub const NFULA_HWADDR: u16 = libc::NFULA_HWADDR as u16;
pub const NFULA_PAYLOAD: u16 = libc::NFULA_PAYLOAD as u16;
pub const NFULA_PREFIX: u16 = libc::NFULA_PREFIX as u16;
pub const NFULA_UID: u16 = libc::NFULA_UID as u16;
pub const NFULA_SEQ: u16 = libc::NFULA_SEQ as u16;
pub const NFULA_SEQ_GLOBAL: u16 = libc::NFULA_SEQ_GLOBAL as u16;
pub const NFULA_GID: u16 = libc::NFULA_GID as u16;
pub const NFULA_HWTYPE: u16 = libc::NFULA_HWTYPE as u16;
pub const NFULA_HWHEADER: u16 = libc::NFULA_HWHEADER as u16;
pub const NFULA_HWLEN: u16 = libc::NFULA_HWLEN as u16;
pub const NFULA_CT: u16 = libc::NFULA_CT as u16;
pub const NFULA_CT_INFO: u16 = libc::NFULA_CT_INFO as u16;

pub const NFULNL_MSG_CONFIG: u8 = libc::NFULNL_MSG_CONFIG as u8;
pub const NFULNL_MSG_PACKET: u8 = libc::NFULNL_MSG_PACKET as u8;
