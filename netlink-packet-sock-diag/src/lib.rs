// SPDX-License-Identifier: MIT

#[macro_use]
extern crate bitflags;

#[macro_use]
pub(crate) extern crate netlink_packet_utils as utils;
pub(crate) use self::utils::parsers;
pub use self::utils::{traits, DecodeError};
pub use netlink_packet_core::{
    ErrorMessage,
    NetlinkBuffer,
    NetlinkHeader,
    NetlinkMessage,
    NetlinkPayload,
};
pub(crate) use netlink_packet_core::{NetlinkDeserializable, NetlinkSerializable};

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate smallvec;

pub mod buffer;
pub mod constants;
pub mod inet;
pub mod message;
pub mod unix;
pub use self::{buffer::*, constants::*, message::*};
