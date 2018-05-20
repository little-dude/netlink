use constants;
use libc;

pub const AF_UNSPEC: u16 = libc::AF_UNSPEC as u16;
pub const AF_UNIX: u16 = libc::AF_UNIX as u16;
pub const AF_INET: u16 = libc::AF_INET as u16;
pub const AF_AX25: u16 = libc::AF_AX25 as u16;
pub const AF_IPX: u16 = libc::AF_IPX as u16;
pub const AF_APPLETALK: u16 = libc::AF_APPLETALK as u16;
pub const AF_NETROM: u16 = libc::AF_NETROM as u16;
pub const AF_BRIDGE: u16 = libc::AF_BRIDGE as u16;
pub const AF_ATMPVC: u16 = libc::AF_ATMPVC as u16;
pub const AF_X25: u16 = libc::AF_X25 as u16;
pub const AF_INET6: u16 = libc::AF_INET6 as u16;

pub const IFLA_INET_UNSPEC: u16 = constants::IFLA_INET_UNSPEC as u16;
pub const IFLA_INET_CONF: u16 = constants::IFLA_INET_CONF as u16;

pub const IFLA_INET6_UNSPEC: u16 = constants::IFLA_INET6_UNSPEC as u16;
pub const IFLA_INET6_FLAGS: u16 = constants::IFLA_INET6_FLAGS as u16;
pub const IFLA_INET6_CONF: u16 = constants::IFLA_INET6_CONF as u16;
pub const IFLA_INET6_STATS: u16 = constants::IFLA_INET6_STATS as u16;
// pub const IFLA_INET6_MCAST: u16 = constants::IFLA_INET6_MCAST as u16;
pub const IFLA_INET6_CACHEINFO: u16 = constants::IFLA_INET6_CACHEINFO as u16;
pub const IFLA_INET6_ICMP6STATS: u16 = constants::IFLA_INET6_ICMP6STATS as u16;
pub const IFLA_INET6_TOKEN: u16 = constants::IFLA_INET6_TOKEN as u16;
pub const IFLA_INET6_ADDR_GEN_MODE: u16 = constants::IFLA_INET6_ADDR_GEN_MODE as u16;
