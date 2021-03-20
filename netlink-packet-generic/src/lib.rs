//! This crate provides the packet of generic netlink family and its controller.
//!
//! The `[GenlMessage]` provides a generic netlink family message which is sub-protocol independant.
//! You can wrap your message into the type, then it can be used in `netlink-proto` crate.
//!
//! # Implementing a generic netlink family
//! TODO

#[macro_use]
extern crate netlink_packet_utils;

pub mod buffer;
pub use self::buffer::*;

pub mod constants;

pub mod ctrl;

pub mod header;
pub use self::header::*;

pub mod message;
pub use self::message::*;

pub mod traits;
pub use self::traits::*;
