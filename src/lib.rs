#![feature(custom_attribute)]
#[macro_use]
extern crate futures;

extern crate byteorder;
extern crate core;
extern crate libc;
extern crate mio;
extern crate tokio_reactor;

pub mod constants;
pub mod packet;
pub mod socket;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
