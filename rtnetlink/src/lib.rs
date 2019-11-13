//! This crate provides methods to manipulate networking resources (links, addresses, arp tables,
//! route tables) via the netlink protocol.

#![allow(clippy::module_inception)]

use failure;

mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

mod link;
pub use crate::link::*;

mod addr;
pub use crate::addr::*;

mod route;
pub use crate::route::*;

mod connection;
pub use crate::connection::*;

pub mod constants;

pub use netlink_packet_route as packet;
pub use netlink_proto::sys;
