//! This package contains types that represent netlink messages. See the [`libnl` library
//! documentation][libnl] for an introduction to the Netlink protocols.
//!
//! Currently, only a subset of the `NETLINK_ROUTE` family has been implemented. It is available in
//! [`packet::rtnl`]. On the long term, I intend to support a few additional netlink families
//! (see `man 7 netlink` for a complete list of protocol families).
//!
//! [`packet::rtnl`]: rtnl/index.html
//! [libnl]: https://www.infradead.org/~tgr/libnl/doc/core.html#core_netlink_fundamentals

/// A collections of constants used in this package
pub mod constants;

mod buffer;
pub use self::buffer::*;

pub(crate) mod common;
pub use self::common::{Error, Result};

mod flags;
pub use self::flags::*;

mod header;
pub use self::header::*;

/// rtnetlink types (see `man 7 rtnetlink`)
pub mod rtnl;
