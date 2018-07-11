//! This package contains types that represent netlink messages. See the [`libnl` library
//! documentation][libnl] for an introduction to the Netlink protocols.
//!
//! Currently, only a subset of the `NETLINK_ROUTE` family has been implemented. It is available in
//! [`packet::rtnl`]. On the long term, I intend to support a few additional netlink families
//! (see `man 7 netlink` for a complete list of protocol families).
//!
//! [`packet::rtnl`]: rtnl/index.html
//! [libnl]: https://www.infradead.org/~tgr/libnl/doc/core.html#core_netlink_fundamentals

use core::ops::{Range, RangeFrom};

/// Represent a multi-bytes field with a fixed size in a packet
pub(crate) type Field = Range<usize>;
/// Represent a field that starts at a given index in a packet
pub(crate) type Rest = RangeFrom<usize>;
/// Represent a field of exactly one byte in a packet
pub(crate) type Index = usize;

mod buffer;
pub use self::buffer::*;

mod flags;
pub use self::flags::*;

mod header;
pub use self::header::*;

/// rtnetlink types (see `man 7 rtnetlink`)
mod rtnl;
pub use self::rtnl::*;

// FIXME: should we expose these traits or only keep them for internal use?
mod traits;
pub use self::traits::*;

mod error;
pub use self::error::*;

mod nla;
pub use self::nla::*;

pub(crate) mod utils;
