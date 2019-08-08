pub use netlink_packet_core::{DecodeError, EncodeError};

use core::ops::Range;
/// Represent a multi-bytes field with a fixed size in a packet
pub(crate) type Field = Range<usize>;

pub mod status;
pub use self::status::*;

// 1000 - 1099 are for commanding the audit system
// 1100 - 1199 user space trusted application messages
// 1200 - 1299 messages internal to the audit daemon
// 1300 - 1399 audit event messages
// 1400 - 1499 SE Linux use
// 1500 - 1599 kernel LSPP events
// 1600 - 1699 kernel crypto events
// 1700 - 1799 kernel anomaly records
// 1800 - 1899 kernel integrity events
// 1900 - 1999 future kernel use
// 2000 is for otherwise unclassified kernel audit messages (legacy)
// 2001 - 2099 unused (kernel)
// 2100 - 2199 user space anomaly records
// 2200 - 2299 user space actions taken in response to anomalies
// 2300 - 2399 user space generated LSPP events
// 2400 - 2499 user space crypto events
// 2500 - 2999 future user space (maybe integrity labels and related events)
pub mod rules;

mod message;
pub use self::message::*;

mod buffer;
pub use self::buffer::*;

mod traits;
pub(crate) use self::traits::*;

pub mod archs;
pub mod commands;
pub mod constants;
pub mod events;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
