pub use self::netlink::DecodeError;
pub use netlink_packet_core as netlink;
pub mod rtnl;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
