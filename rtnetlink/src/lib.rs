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
//! use std::env;
//! use std::thread::spawn;
//!
//! use futures::{Stream, Future};
//! use tokio_core::reactor::Core;
//!
//! use rtnetlink::new_connection;
//! use netlink_packet_route::link::nlas::LinkNla;
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
//!     let links = handle.link().get().execute().collect().wait().unwrap();
//!
//!     // Find the link with the name provided as argument, and delete it
//!     for link in links {
//!         for nla in &link.nlas {
//!             // Find the link with the name provided as argument
//!             if let LinkNla::IfName(ref name) = nla {
//!                 if name == link_name {
//!                     // Set it down
//!                     handle.link().del(link.header.index).execute().wait().unwrap();
//!                     return;
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```

#![allow(clippy::module_inception)]

#[macro_use]
extern crate lazy_static;

use failure;

pub use netlink_packet_core;
pub use netlink_packet_route;
use netlink_proto;
pub use netlink_proto::{sys::Protocol, Connection};

mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

mod link;
pub use crate::link::*;

mod addr;
pub use crate::addr::*;

use std::io;

use crate::netlink_packet_core::NetlinkMessage;
use crate::netlink_packet_route::RtnlMessage;
use futures::sync::mpsc::UnboundedReceiver;

pub fn new_connection() -> io::Result<(Connection<RtnlMessage>, Handle)> {
    let (conn, handle, _) = netlink_proto::new_connection(Protocol::Route)?;
    Ok((conn, Handle::new(handle)))
}

pub fn new_connection_with_messages() -> io::Result<(
    Connection<RtnlMessage>,
    Handle,
    UnboundedReceiver<NetlinkMessage<RtnlMessage>>,
)> {
    let (conn, handle, messages) = netlink_proto::new_connection(Protocol::Route)?;
    Ok((conn, Handle::new(handle), messages))
}
