//! `netlink-proto` is an asynchronous implementation of the Netlink
//! protocol.
//!
//! # Example: listening for audit events
//!
//! This example shows how to use `netlink-proto` with the `tokio`
//! runtime to print audit events. It requires extra external
//! dependencies:
//!
//! - `futures = "^0.1"`
//! - `failure = "^0.1"`
//! - `tokio = "^0.1"`
//! - `netlink-packet-audit = "^0.1"`
//!
//! ```rust,no_run
//! use std::process;
//! use failure::Fail; // failure 0.1.5
//! use futures::{ // futures 0.1.28
//!     future::{lazy, Future},
//!     stream::Stream,
//! };
//! use netlink_packet_audit::{AuditMessage, StatusMessage}; // netlink-packet-audit 0.1
//! use netlink_proto::{
//!     new_connection,
//!     packet::{
//!         header::flags::{NLM_F_ACK, NLM_F_REQUEST},
//!         NetlinkFlags, NetlinkMessage, NetlinkPayload,
//!     },
//!     sys::{Protocol, SocketAddr},
//! };
//!
//! const AUDIT_STATUS_ENABLED: u32 = 1;
//! const AUDIT_STATUS_PID: u32 = 4;
//!
//! fn main() {
//!     let (conn, mut handle, messages) =
//!         new_connection(Protocol::Audit).expect("Failed to create a new netlink connection");
//!
//!     // We'll send unicast messages to the kernel.
//!     let kernel_unicast: SocketAddr = SocketAddr::new(0, 0);
//!
//!     tokio::run(lazy(move || {
//!         // Spawn the `netlink_proto::Connection` so that it starts
//!         // polling the netlink socket.
//!         tokio::spawn(conn.map_err(|e| eprintln!("error in connection: {:?}", e)));
//!
//!         // Use the `netlink_proto::ConnectionHandle` to send a request
//!         // to the kernel asking it to start multicasting audit event messages.
//!         tokio::spawn({
//!             // Craft the packet to enable audit events
//!             let mut status = StatusMessage::new();
//!             status.enabled = 1;
//!             status.pid = process::id();
//!             status.mask = AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID;
//!             let payload = AuditMessage::SetStatus(status);
//!             let mut nl_msg = NetlinkMessage::from(payload);
//!             nl_msg.header.flags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK);
//!
//!             // The ConnectionHandle::request() method returns a
//!             // Stream<Item=NetlinkMessage<AuditMessage>>, although
//!             // here we only expects one message in return: either an
//!             // ACK or an ERROR.
//!             handle
//!                 .request(nl_msg, kernel_unicast)
//!                 // For simplicity we'll use strings for errors in this
//!                 // example. This netlink-proto uses the `failure`
//!                 // crate, errors contain the whole chain of errors
//!                 // that led to this error. `format_failure_error`
//!                 // format them nicely
//!                 .map_err(format_failure_error)
//!                 .for_each(|message| {
//!                     if let NetlinkPayload::Error(err_message) = message.payload {
//!                         Err(format!("Received an error message: {:?}", err_message))
//!                     } else {
//!                         Ok(())
//!                     }
//!                 })
//!                 .map_err(|e| eprintln!("Request failed: {:?}", e))
//!         });
//!
//!         println!("Starting to print audit events... press ^C to interrupt");
//!
//!         // We print the audit event messages that the kernel multicasts.
//!         messages.for_each(|message| {
//!             println!("{:?}", message);
//!             Ok(())
//!         })
//!     }))
//! }
//!
//! fn format_failure_error<E: Fail>(error: E) -> String {
//!     let mut error_string = String::new();
//!     for cause in Fail::iter_chain(&error) {
//!         error_string += &format!(": {}", cause);
//!     }
//!     error_string
//! }
//! ```
//!
//! # Example: dumping all the machine's links
//!
//! This example shows how to use `netlink-proto` with the ROUTE
//! protocol.

//! Here we do not use `netlink_proto::new_connection()`, and instead
//! create the socket manually and use call `send()` and `receive()`
//! directly. In the previous example, the `NetlinkFramed` was wrapped
//! in a `Connection` which was polled automatically by the runtime.
//!
//! ```rust,no_run
//! use futures::{Future, Sink, Stream};
//!
//! use netlink_packet_route::{
//!     link::{LinkHeader, LinkMessage},
//!     RtnlMessage,
//! };
//!
//! use netlink_proto::{
//!     packet::{
//!         header::flags::{NLM_F_DUMP, NLM_F_REQUEST},
//!         NetlinkFlags, NetlinkHeader, NetlinkMessage, NetlinkPayload,
//!     },
//!     sys::{Protocol, SocketAddr, TokioSocket},
//!     NetlinkCodec, NetlinkFramed,
//! };
//!
//! fn main() {
//!     let mut socket = TokioSocket::new(Protocol::Route).unwrap();
//!     // We could use the port number if we were interested in it.
//!     let _port_number = socket.bind_auto().unwrap().port_number();
//!     socket.connect(&SocketAddr::new(0, 0)).unwrap();
//!
//!     // `NetlinkFramed<RtnlMessage>` wraps the socket and provides
//!     // Stream and Sink implementations for the messages.
//!     let stream = NetlinkFramed::new(socket, NetlinkCodec::<NetlinkMessage<RtnlMessage>>::new());
//!
//!     // Create the payload for the request.
//!     let payload: NetlinkPayload<RtnlMessage> =
//!         RtnlMessage::GetLink(LinkMessage::from_parts(LinkHeader::new(), vec![])).into();
//!
//!     // Create the header for the request
//!     let mut header = NetlinkHeader::new();
//!     header.flags = NetlinkFlags::from(NLM_F_DUMP | NLM_F_REQUEST);
//!     header.sequence_number = 1;
//!
//!     // Create the netlink packet itself
//!     let mut packet = NetlinkMessage::new(header, payload);
//!     // `finalize` is important: it garantees the header is consistent
//!     // with the packet's payload. Having incorrect header can lead to
//!     // a panic when the message is serialized.
//!     packet.finalize();
//!
//!     // Serialize the packet and send it
//!     let mut buf = vec![0; packet.header.length as usize];
//!     packet.serialize(&mut buf[..packet.buffer_len()]);
//!     println!(">>> {:?}", packet);
//!     let stream = stream.send((packet, SocketAddr::new(0, 0))).wait().unwrap();
//!
//!     // Print all the incoming message (press ^C to exit)
//!     stream
//!         .for_each(|(packet, _addr)| {
//!             println!("<<< {:?}", packet);
//!             Ok(())
//!         })
//!         .wait()
//!         .unwrap();
//! }
//! ```
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;

mod codecs;
pub use crate::codecs::*;

mod framed;
pub use crate::framed::*;

mod connection;
pub use crate::connection::*;

mod errors;
pub use crate::errors::*;

mod handle;
pub use crate::handle::*;

mod request;
pub(crate) use crate::request::Request;

pub use netlink_packet_core as packet;
pub use netlink_sys as sys;

use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use std::fmt::Debug;
use std::io;

use self::packet::{NetlinkDeserializable, NetlinkMessage, NetlinkSerializable};
use self::sys::Protocol;

/// Create a new Netlink connection for the given Netlink protocol,
/// and returns a handle to that connection as well as a stream of
/// un-sollicited messages received by that connection (un-sollicited
/// here means messages that are not a response to a request made by
/// the `Connection`). `Connection<T>` wraps a Netlink socket and
/// implements the Netlink protocol.
///
/// `T` is the type of netlink messages used for this protocol. For
/// instance, if you're using the AUDIT protocol with the
/// `netlink-packet-audit` crate, `T` will be
/// `netlink_packet_audit::AuditMessage`. More generaly, `T` is
/// anything that can be serialized and deserialized into a Netlink
/// message. See the `netlink_packet_core` documentation for details
/// about the `NetlinkSerializable` and `NetlinkDeserializable`
/// traits.
///
/// Most of the time, users will want to spawn the `Connection` on an
/// async runtime, and use the handle to send messages.
pub fn new_connection<T>(
    protocol: Protocol,
) -> io::Result<(
    Connection<T>,
    ConnectionHandle<T>,
    UnboundedReceiver<NetlinkMessage<T>>,
)>
where
    T: Debug + PartialEq + Eq + Clone + NetlinkSerializable<T> + NetlinkDeserializable<T>,
{
    let (requests_tx, requests_rx) = unbounded::<Request<T>>();
    let (messages_tx, messages_rx) = unbounded::<NetlinkMessage<T>>();
    Ok((
        Connection::new(requests_rx, messages_tx, protocol)?,
        ConnectionHandle::new(requests_tx),
        messages_rx,
    ))
}
