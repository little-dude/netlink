// SPDX-License-Identifier: MIT

//! This crate provides methods to manipulate IPsec tunnel resources (policies, SAs)
//! via the netlink protocol.

#![allow(clippy::module_inception)]

pub use netlink_packet_xfrm as packet;
pub mod proto {
    pub use netlink_proto::{
        packet::{NetlinkMessage, NetlinkPayload},
        Connection, ConnectionHandle, Error,
    };
}
pub use netlink_proto::sys;

mod connection;
pub use crate::connection::*;

pub mod constants;
pub use crate::constants::*;

mod errors;
pub use crate::errors::*;

mod handle;
pub use crate::handle::*;

mod macros;

mod policy;
pub use crate::policy::*;

mod state;
pub use crate::state::*;
