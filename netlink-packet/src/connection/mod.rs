mod connection;
mod handle;
mod utils;

mod codecs;
mod framed;

pub use self::connection::*;
pub use self::handle::*;

use futures::sync::mpsc::{unbounded, UnboundedSender};
use packets::NetlinkMessage;
use std::io;

/// Create a new connection and a handle to pass requests to it. The connection is a future (see
/// [`Connection`](struct.Connection.html), so once created, it needs to be run on a task executor,
/// for example an event loop:
///
/// # Example
///
/// ```rust,no_run
/// extern crate futures;
/// extern crate rtnetlink;
/// extern crate tokio_core;
///
/// use futures::{Stream, Future};
/// use tokio_core::reactor::Core;
///
/// use rtnetlink::constants::{NLM_F_REQUEST, NLM_F_DUMP};
/// use rtnetlink::packet::{NetlinkFlags, RtnlMessage, NetlinkMessage, NetlinkPayload, LinkNla, LinkMessage};
/// use rtnetlink::{new_connection};
///
/// fn main() {
///     // Create an event loop to run the connection and the request
///     let mut event_loop = Core::new().unwrap();
///
///     // Create the connection and a handle to pass requests to it
///     let (connection, mut handle) = new_connection().unwrap();
///
///     // Spawn the connection on the event loop. This is when the netlink socket is actually opened.
///     event_loop.handle().spawn(connection.map_err(|_| ()));
///
///     // Build a request to dump the links. A request is just a netlink message with the
///     // NLM_F_REQUEST flag set.
///     let mut req = NetlinkMessage::from(RtnlMessage::GetLink(LinkMessage::new()));
///     req.header_mut().set_flags(NetlinkFlags::from(NLM_F_REQUEST | NLM_F_DUMP));
///
///     // Build the request. This looks a bit clumsy and there is not error handling at all, but this
///     // crate already provides more convenient methods to run similar requests. This is just for the
///     // example.
///     let future = handle.request(req)
///         .map_err(|e| eprintln!("{}", e))
///         // The response is a stream of netlink messages. Here, we handle the message
///         .for_each(|msg| {
///             // If the message is an error, print the message and return an error to stop the stream
///             if msg.is_error() {
///                 eprintln!("error: {:?}", msg);
///                 return Err(());
///             }
///             // If is an RTM_NEWLINK message,find the attribute corresponding to the link name and
///             // print it
///             let payload = msg.payload().clone();
///             if let NetlinkPayload::Rtnl(RtnlMessage::NewLink(link_msg)) = payload {
///                 for nla in link_msg.nlas() {
///                     if let LinkNla::IfName(ref name) = nla {
///                         println!("found link {}", name);
///                     }
///                 }
///             } else {
///                 // Otherwise, we don't know how to handle the message, so just print an error
///                 eprintln!("unexpected message: {:?}", msg);
///                 return Err(());
///             }
///             Ok(())
///         });
///
///     // run the request
///     event_loop.run(future).unwrap()
/// }
/// ```
pub fn new_connection() -> io::Result<(Connection, ConnectionHandle)> {
    let (tx, rx) = unbounded::<(UnboundedSender<NetlinkMessage>, NetlinkMessage)>();
    Ok((Connection::new(rx)?, ConnectionHandle::new(tx)))
}
