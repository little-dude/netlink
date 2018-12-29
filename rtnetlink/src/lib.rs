//! This crate provides methods to manipulate networking resources (links, addresses, arp tables,
//! route tables) via the netlink protocol.
//!
//! It can be used on its own for simple needs, but it is possible to tweak any netlink request.
//! See this [link creation snippet](struct.LinkAddRequest.html#example) for example.
//!
//! # Example: listing links
//!
//! ```rust,no_run
//! extern crate futures;
//! extern crate rtnetlink;
//! extern crate tokio_core;
//!
//! use futures::{Stream, Future};
//! use rtnetlink::new_connection;
//! use tokio_core::reactor::Core;
//!
//! fn main() {
//!     // Create a netlink connection, and a handle to send requests via this connection
//!     let (connection, handle) = new_connection().unwrap();
//!
//!     // The connection will run in an event loop
//!     let mut core = Core::new().unwrap();
//!     core.handle().spawn(connection.map_err(|_| ()));
//!
//!     /// Create a netlink request
//!     let request = handle.link().get().execute().for_each(|link| {
//!         println!("{:#?}", link);
//!         Ok(())
//!     });
//!
//!     /// Run the request on the event loop
//!     core.run(request).unwrap();
//! }
//! ```
//!
//! # Example: creating a veth pair
//!
//! ```rust,no_run
//! extern crate futures;
//! extern crate rtnetlink;
//! extern crate tokio_core;
//!
//! use std::thread::spawn;
//!
//! use futures::Future;
//! use tokio_core::reactor::Core;
//!
//! use rtnetlink::new_connection;
//!
//! fn main() {
//!     // Create a netlink connection, and a handle to send requests via this connection
//!     let (connection, handle) = new_connection().unwrap();
//!
//!     // The connection we run in its own thread
//!     spawn(move || Core::new().unwrap().run(connection));
//!
//!     // Create a request to create the veth pair
//!     handle
//!         .link()
//!         .add()
//!         .veth("veth-rs-1".into(), "veth-rs-2".into())
//!         // Execute the request, and wait for it to finish
//!         .execute()
//!         .wait()
//!         .unwrap();
//! }
//! ```
//!
//! # Example: deleting a link by name
//!
//! ```rust,no_run
//! extern crate futures;
//! extern crate rtnetlink;
//! extern crate tokio_core;
//!
//! use std::env;
//! use std::thread::spawn;
//!
//! use futures::{Stream, Future};
//! use tokio_core::reactor::Core;
//!
//! use rtnetlink::new_connection;
//!
//! fn main() {
//!     let args: Vec<String> = env::args().collect();
//!     if args.len() != 2 { panic!("expected one link name as argument"); }
//!     let link_name = &args[1];
//!
//!     let (connection, handle) = new_connection().unwrap();
//!     spawn(move || Core::new().unwrap().run(connection));
//!
//!     // Get the list of links
//!     let links = handle.link().get().execute().wait();
//!
//!     // Find the link with the name provided as argument, and delete it
//!     for link in links {
//!         let link = link.unwrap();
//!         if link.name().unwrap() == link_name {
//!             handle.link().del(link.index()).execute().wait();
//!         }
//!     }
//! }
//! ```

#![allow(clippy::module_inception)]

extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate bytes;
extern crate eui48;
extern crate failure;
extern crate failure_derive;
extern crate futures;
extern crate ipnetwork;
extern crate tokio;
extern crate tokio_core;

pub extern crate netlink_packet as packet;
pub use crate::packet::constants;
extern crate netlink_proto;
pub use netlink_proto::{Connection, Protocol};

mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

mod link;
pub use crate::link::*;

mod addr;
pub use crate::addr::*;

use std::io;

pub fn new_connection() -> io::Result<(Connection, Handle)> {
    let (conn, handle, _) = netlink_proto::new_connection(Protocol::Route)?;
    Ok((conn, Handle::new(handle)))
}
