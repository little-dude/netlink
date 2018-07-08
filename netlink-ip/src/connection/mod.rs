mod connection;
mod handle;
mod utils;

pub use self::connection::*;
pub use self::handle::*;
pub(crate) use self::utils::*;

use futures::sync::mpsc::{unbounded, UnboundedSender};
use netlink_sys::rtnl::Message;
use std::io;

pub fn new_connection() -> io::Result<(Connection, ConnectionHandle)> {
    let (tx, rx) = unbounded::<(UnboundedSender<Message>, Message)>();
    Ok((Connection::new(rx)?, ConnectionHandle::new(tx)))
}
