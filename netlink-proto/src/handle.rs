use futures::sync::mpsc::{unbounded, UnboundedSender};
use futures::Stream;
use netlink_packet_core::NetlinkMessage;
use std::fmt::Debug;

use crate::errors::{Error, ErrorKind};
use crate::Request;
use netlink_sys::SocketAddr;

/// A handle to pass requests to a [`Connection`](struct.Connection.html).
#[derive(Clone, Debug)]
pub struct ConnectionHandle<T>
where
    T: Debug + Clone + Eq + PartialEq,
{
    requests_tx: UnboundedSender<Request<T>>,
}

impl<T> ConnectionHandle<T>
where
    T: Debug + Clone + Eq + PartialEq,
{
    pub(crate) fn new(requests_tx: UnboundedSender<Request<T>>) -> Self {
        ConnectionHandle { requests_tx }
    }

    /// Send a new request and get the response as a stream of messages. Note that some messages
    /// are not part of the response stream:
    ///
    /// - **acknowledgements**: when an acknowledgement is received, the stream is closed
    /// - **end of dump messages**: similarly, upon receiving an "end of dump" message, the stream is
    /// closed
    pub fn request(
        &mut self,
        message: NetlinkMessage<T>,
        destination: SocketAddr,
    ) -> impl Stream<Item = NetlinkMessage<T>, Error = Error<T>> {
        let (tx, rx) = unbounded::<NetlinkMessage<T>>();
        let request = Request::from((tx, message, destination));
        debug!("handle: forwarding new request to connection");
        // We don't handle the error here, because we would have to return a Result, which makes
        // the signature of this method pretty ugly. If this fails, we know that the receiver has
        // been dropped, so the request (and the tx channed it contains) will be dropped when this
        // function returns. Then rx.poll() will return the error we want.
        let _ = UnboundedSender::unbounded_send(&self.requests_tx, request);
        rx.map_err(|()| {
            error!("could not forward new request to connection: the connection is closed");
            ErrorKind::ConnectionClosed.into()
        })
    }

    pub fn notify(
        &mut self,
        message: NetlinkMessage<T>,
        destination: SocketAddr,
    ) -> Result<(), Error<T>> {
        let (tx, _rx) = unbounded::<NetlinkMessage<T>>();
        let request = Request::from((tx, message, destination));
        debug!("handle: forwarding new request to connection");
        UnboundedSender::unbounded_send(&self.requests_tx, request)
            .map_err(|_| ErrorKind::ConnectionClosed.into())
    }
}
