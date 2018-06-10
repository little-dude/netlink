#![feature(tool_attributes)]
#![feature(custom_attribute)]
#![allow(unused_attributes)]
#![rustfmt::skip]

#[macro_use]
extern crate log;
extern crate byteorder;
extern crate bytes;
extern crate core;
extern crate libc;

pub mod constants;

// We do not re-export all the constants. They are used internally and re-exported in submodules.
mod bindgen_constants;
/// Types representing netlink packets, and providing message serialization and deserialization.
mod packet;
pub use self::packet::*;
/// Netlink socket.
mod socket;
pub use self::socket::*;

// Mio
#[cfg(feature = "mio_support")] extern crate mio;

// Tokio
#[cfg(feature = "tokio_support")] #[macro_use] extern crate futures;
#[cfg(feature = "tokio_support")] extern crate tokio_io;
#[cfg(feature = "tokio_support")] extern crate tokio_reactor;
#[cfg(feature = "tokio_support")] mod framed;
#[cfg(feature = "tokio_support")] mod codecs;
#[cfg(feature = "tokio_support")] pub use self::framed::*;

// Tests
#[cfg(test)] #[macro_use] extern crate lazy_static;
