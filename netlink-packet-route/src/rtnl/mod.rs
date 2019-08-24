pub mod address;
pub mod link;
pub mod neighbour;
pub mod neighbour_table;
pub mod nla;
pub mod nsid;
pub mod route;
pub mod tc;

pub mod buffer;
pub use self::buffer::*;
pub mod message;
pub use self::message::*;
pub mod message_types;
pub use self::message_types::*;

#[cfg(test)]
mod test;

pub mod traits;
pub(crate) mod utils;

use core::ops::{Range, RangeFrom};
/// Represent a multi-bytes field with a fixed size in a packet
pub(crate) type Field = Range<usize>;
/// Represent a field that starts at a given index in a packet
pub(crate) type Rest = RangeFrom<usize>;
/// Represent a field of exactly one byte in a packet
pub(crate) type Index = usize;
