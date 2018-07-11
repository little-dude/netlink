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
