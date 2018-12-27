//! This package contains types that represent netlink messages. See the [`libnl` library
//! documentation][libnl] for an introduction to the Netlink protocols.
//!
//! Currently, only a subset of the `NETLINK_ROUTE` family has been implemented. It is available in
//! [`packet::rtnl`]. On the long term, I intend to support a few additional netlink families
//! (see `man 7 netlink` for a complete list of protocol families).
//!
//! [`rtnl`]: rtnl/index.html
//! [libnl]: https://www.infradead.org/~tgr/libnl/doc/core.html#core_netlink_fundamentals
//!
//! # Messages
//!
//! This crate provides two representations of most netlink packets:
//!
//! - **Buffer** types: [`NetlinkBuffer`](struct.NetlinkBuffer.html),
//! [`LinkBuffer`](struct.LinkBuffer.html), [`NlaBuffer`](struct.NlaBuffer.html), etc. These types
//! wrappers around actual byte buffers, and provide safe accessors to the various fields of the
//! packet they represent. These types are useful if you manipulate byte streams, but everytime
//! data is accessed, it must be parsed or encoded.
//!
//! - **Message** and **Nla** types: [`NetlinkMessage`](struct.NetlinkMessage.html),
//! [`LinkMessage`](struct.LinkMessage.html), [`LinkNla`](struct.LinkNla.html),
//! [`AddressNla`](struct.AddressNla.html) etc. These are higher level representations of netlink
//! packets and are the prefered way to build packets.
//!
//! ## Using buffer types to parse messages
//!
//! It is possible to go from on representation to another. Actually, the buffer types are used to
//! parse byte buffers into messages types, using the [`Parseable`](trait.Parseable.html) trait. In
//! the list of implementors, we can see for instance:
//!
//! ```no_rust
//! impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NetlinkMessage> for NetlinkBuffer<&'buffer T>
//! ```
//!
//! That means a `NetlinkBuffer` is parseable into a `NetlinkMessage`:
//!
//! ```rust
//! extern crate netlink_packet;
//! use netlink_packet::{NetlinkBuffer, NetlinkMessage, Parseable};
//! use netlink_packet::constants::{RTM_GETLINK, NLM_F_ROOT, NLM_F_REQUEST, NLM_F_MATCH};
//!
//! // a packet captured with tcpdump that was sent when running `ip link show`
//! static PKT: [u8; 40] = [
//!     0x28, 0x00, 0x00, 0x00, // length
//!     0x12, 0x00, // message type
//!     0x01, 0x03, // flags
//!     0x34, 0x0e, 0xf9, 0x5a, // sequence number
//!     0x00, 0x00, 0x00, 0x00, // port id
//!     // payload
//!     0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x08, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x00];
//!
//! fn main() {
//!     let pkt: NetlinkMessage =
//!         // Create a buffer. Notice the double &&. That is because Parseable<NetlinkMessage> is
//!         // implemented for NetlinkBuffer<&T> not NetlinkBuffer<T>. The reason behing this is
//!         // that we want the storage T to be able to outlive our NetlinkBuffer, if necessary. It
//!         // feels a bit weird here but can be useful in other circumstances.
//!         NetlinkBuffer::new_checked(&&PKT[..])
//!             .unwrap()
//!             // Convert the buffer into an actual message. This is when the parsing occurs.
//!             .parse()
//!             .unwrap();
//!
//!     println!("{:#?}", pkt);
//! }
//! ```
//!
//! This prints:
//!
//! ```no_rust
//! NetlinkMessage {
//!     header: NetlinkHeader {
//!         length: 40,
//!         message_type: 18,
//!         flags: NetlinkFlags(769),
//!         sequence_number: 1526271540,
//!         port_number: 0
//!     },
//!     message: GetLink(
//!         LinkMessage {
//!             header: LinkHeader {
//!                 address_family: 17,
//!                 index: 0,
//!                 link_layer_type: Netrom,
//!                 flags: LinkFlags(0),
//!                 change_mask: LinkFlags(0)
//!             },
//!             nlas: [ExtMask(1)]
//!         }
//!     ),
//! }
//! ```
//!
//! ## Emitting messages
//!
//! TODO

#![cfg_attr(rustfmt, rustfmt::skip)]
#![allow(clippy::new_without_default_derive)]

extern crate byteorder;
extern crate bytes;
extern crate core;
extern crate failure;
extern crate libc;
#[macro_use] extern crate log;

extern crate netlink_sys;
pub use netlink_sys::constants;

mod errors;
pub use self::errors::*;

use core::ops::{Range, RangeFrom};
/// Represent a multi-bytes field with a fixed size in a packet
pub(crate) type Field = Range<usize>;
/// Represent a field that starts at a given index in a packet
pub(crate) type Rest = RangeFrom<usize>;

#[cfg(feature = "rtnetlink")]
/// Represent a field of exactly one byte in a packet
pub(crate) type Index = usize;

#[cfg(feature = "rtnetlink")]
/// rtnetlink types (see `man 7 rtnetlink`)
mod rtnl;
#[cfg(feature = "rtnetlink")]
pub use self::rtnl::*;

mod netlink;
pub use self::netlink::*;

// FIXME: should we expose these traits or only keep them for internal use?
mod traits;
pub use self::traits::*;

#[cfg(test)] #[macro_use] extern crate lazy_static;
