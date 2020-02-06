pub mod address;
pub use address::{AddressHeader, AddressMessage, AddressMessageBuffer, ADDRESS_HEADER_LEN};

pub mod link;
pub use link::{LinkHeader, LinkMessage, LinkMessageBuffer, LINK_HEADER_LEN};

pub mod neighbour;
pub use neighbour::{
    NeighbourHeader, NeighbourMessage, NeighbourMessageBuffer, NEIGHBOUR_HEADER_LEN,
};

pub mod neighbour_table;
pub use neighbour_table::{
    NeighbourTableHeader, NeighbourTableMessage, NeighbourTableMessageBuffer,
    NEIGHBOUR_TABLE_HEADER_LEN,
};

pub mod nsid;
pub use nsid::{NsidHeader, NsidMessage, NsidMessageBuffer, NSID_HEADER_LEN};

pub mod route;
pub use route::{RouteFlags, RouteHeader, RouteMessage, RouteMessageBuffer, ROUTE_HEADER_LEN};

pub mod rule;
pub use rule::{RuleHeader, RuleMessage, RuleMessageBuffer, RULE_HEADER_LEN};

pub mod tc;
pub use tc::{TcHeader, TcMessage, TcMessageBuffer, TC_HEADER_LEN};

pub mod constants;
pub use self::constants::*;

mod buffer;
pub use self::buffer::*;

mod message;
pub use self::message::*;

pub mod nlas {
    pub use super::address::nlas as address;
    pub use super::link::nlas as link;
    pub use super::neighbour::nlas as neighbour;
    pub use super::neighbour_table::nlas as neighbour_table;
    pub use super::nsid::nlas as nsid;
    pub use super::route::nlas as route;
    pub use super::rule::nlas as rule;
    pub use super::tc::nlas as tc;
    pub use crate::utils::nla::*;
}

#[cfg(test)]
mod test;
