//! This crate contains building blocks for the route netlink protocol.
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
//! extern crate rtnetlink;
//! use rtnetlink::{NetlinkBuffer, NetlinkMessage, Parseable};
//! use rtnetlink::constants::{RTM_GETLINK, NLM_F_ROOT, NLM_F_REQUEST, NLM_F_MATCH};
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
//!     // Create a buffer. Notice the double &&. That is because Parseable<NetlinkMessage> is
//!     // implemented for NetlinkBuffer<&T> not NetlinkBuffer<T>. The reason behing this is that
//!     // we want the storage T to be able to outlive our NetlinkBuffer, if necessary. It feels a
//!     // bit weird here but can be useful in other circumstances.
//!     let buf = NetlinkBuffer::new_checked(&&PKT[..]).unwrap();
//!
//!     // Convert the buffer into an actual message. This is when the parsing logic occurs.
//!     let pkt: NetlinkMessage = buf.parse().unwrap();
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
//!     finalized: true
//! }
//! ```
//!
//! ## Emitting messages
//!
//! TODO
//!
//!
//! ## Should I use Buffer types or Message type (`NetlinkBuffer` or `NetlinkMessage`)?
//!
//! Message types are much more convenient to work with. They are full blown rust types, and easier
//! to manipulate. I use buffer types mostly as temporary intermediate representations between
//! bytes and message types.
//!
//! However, if you have to treat large quantities of packets and are only interested in a few of
//! them, buffer types may be useful, because they allow to perform quick check on the messages
//! without actually parsing them.
//!
//! TODO
//!
//! # Tokio integration
//!
//! TODO
//!
#![cfg_attr(feature = "nightly", feature(tool_attributes))]
#![cfg_attr(feature = "nightly", feature(custom_attribute))]
#![cfg_attr(feature = "nightly", allow(unused_attributes))]
#![cfg_attr(feature = "nightly", rustfmt::skip)]

extern crate byteorder;
extern crate bytes;
extern crate core;
extern crate libc;

extern crate netlink_socket;

pub mod constants;

// We do not re-export all the constants. They are used internally and re-exported in submodules.
mod bindgen_constants;
/// Types representing netlink packets, and providing message serialization and deserialization.
mod packets;
pub use self::packets::*;

mod errors;
pub use self::errors::*;

// Tokio
#[cfg(feature = "tokio_support")] #[macro_use] extern crate log;
#[cfg(feature = "tokio_support")] #[macro_use] extern crate futures;
#[cfg(feature = "tokio_support")] extern crate tokio_io;
#[cfg(feature = "tokio_support")] extern crate tokio_reactor;
#[cfg(feature = "tokio_support")] mod framed;
#[cfg(feature = "tokio_support")] mod codecs;
#[cfg(feature = "tokio_support")] pub use codecs::*;
#[cfg(feature = "tokio_support")] pub use self::framed::*;

// Tests
#[cfg(test)] #[macro_use] extern crate lazy_static;
