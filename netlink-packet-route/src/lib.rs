use core::ops::{Range, RangeFrom};
use netlink_packet_core::DecodeError;

pub mod address;
pub mod link;
pub mod neighbour;
pub mod neighbour_table;
pub mod nla;
pub mod nsid;
pub mod route;
pub mod tc;
#[cfg(test)]
mod test;
pub mod traits;
pub(crate) mod utils;

mod buffer;
pub use self::buffer::*;

mod message;
pub use self::message::*;

mod message_types;
pub use message_types::*;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

/// Represent a multi-bytes field with a fixed size in a packet
pub(crate) type Field = Range<usize>;
/// Represent a field that starts at a given index in a packet
pub(crate) type Rest = RangeFrom<usize>;
/// Represent a field of exactly one byte in a packet
pub(crate) type Index = usize;
