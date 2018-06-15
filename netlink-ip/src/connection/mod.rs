mod connection;
mod handle;

pub use self::connection::*;
pub use self::handle::*;

use futures::sync::mpsc::{unbounded, UnboundedSender};
use futures::Future;
use netlink_sys::rtnl::Message;
use std::io;
use tokio_core::reactor::Handle;

pub fn new_connection(handle: &Handle) -> io::Result<ConnectionHandle> {
    let (tx, rx) = unbounded::<(UnboundedSender<Message>, Message)>();
    let connection = Connection::new(rx)?;
    handle.spawn(connection.map_err(|_| ()));
    Ok(ConnectionHandle::new(tx))
}
