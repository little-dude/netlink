#![feature(tool_attributes)]
#![feature(custom_attribute)]

#[macro_use]
extern crate log;

extern crate byteorder;
extern crate bytes;
extern crate core;
extern crate libc;

// We do not re-export all the constants. They are used internally and re-exported in submodules.
mod constants;
/// Types representing netlink packets, and providing message serialization and deserialization.
pub mod packet;
/// Netlink socket.
pub mod socket;

// Mio
#[cfg(feature = "mio_support")]
extern crate mio;

// Tokio
#[cfg(feature = "tokio_support")]
#[macro_use]
extern crate futures;

#[cfg(feature = "tokio_support")]
extern crate tokio_io;

#[cfg(feature = "tokio_support")]
extern crate tokio_reactor;

#[cfg(feature = "tokio_support")]
pub mod framed;

// Tests
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
