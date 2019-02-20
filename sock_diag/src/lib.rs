#![allow(clippy::module_inception)]

#[macro_use]
extern crate lazy_static;

pub use crate::packet::constants;
pub use netlink_packet as packet;
use netlink_proto;
pub use netlink_proto::{Connection, Protocol};

mod errors;
pub use crate::errors::ErrorKind;

mod handle;
pub use crate::handle::Handle;

mod inet;
pub use crate::inet::InetHandle;

mod unix;
pub use crate::unix::UnixHandle;

use std::io;

pub fn new_connection() -> io::Result<(Connection, Handle)> {
    let (conn, handle, _) = netlink_proto::new_connection(Protocol::SockDiag)?;
    Ok((conn, Handle::new(handle)))
}
