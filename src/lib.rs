#![feature(tool_attributes)]
#![feature(custom_attribute)]
#[macro_use]
extern crate futures;

#[macro_use]
extern crate log;

extern crate byteorder;
extern crate bytes;
extern crate core;
extern crate libc;
extern crate mio;
extern crate tokio_io;
extern crate tokio_reactor;

pub mod constants;
pub mod framed;
pub mod packet;
pub mod socket;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
