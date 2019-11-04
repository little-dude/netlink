pub(crate) extern crate netlink_packet_utils as utils;
pub use self::utils::{traits, DecodeError};
pub use netlink_packet_core::{
    ErrorMessage, NetlinkBuffer, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
pub(crate) use netlink_packet_core::{NetlinkDeserializable, NetlinkSerializable};

use core::ops::Range;
/// Represent a multi-bytes field with a fixed size in a packet
pub(crate) type Field = Range<usize>;

pub mod status;
pub use self::status::*;

pub mod rules;
pub use self::rules::*;

mod message;
pub use self::message::*;

mod buffer;
pub use self::buffer::*;

pub mod constants;
pub use self::constants::*;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
