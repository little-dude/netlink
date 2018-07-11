#![cfg_attr(feature = "cargo-clippy", allow(module_inception))]

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate bytes;
extern crate eui48;
extern crate futures;
extern crate tokio_core;

extern crate netlink_socket;
extern crate rtnetlink;

extern crate failure;
#[macro_use]
extern crate failure_derive;

mod connection;
mod errors;
mod link;

pub use connection::*;
pub use errors::*;
pub use link::*;
