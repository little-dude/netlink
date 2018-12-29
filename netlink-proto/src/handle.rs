use futures::sync::mpsc::{unbounded, UnboundedSender};
use futures::Stream;
use netlink_packet::NetlinkMessage;

use crate::errors::{Error, ErrorKind};
use netlink_sys::SocketAddr;
use crate::Request;

/// A handle to pass requests to a [`Connection`](struct.Connection.html).
#[derive(Clone, Debug)]
pub struct ConnectionHandle {
    requests_tx: UnboundedSender<Request>,
}

impl ConnectionHandle {
    pub(crate) fn new(requests_tx: UnboundedSender<Request>) -> Self {
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
        message: NetlinkMessage,
        destination: SocketAddr,
    ) -> impl Stream<Item = NetlinkMessage, Error = Error> {
        let (tx, rx) = unbounded::<NetlinkMessage>();
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
        message: NetlinkMessage,
        destination: SocketAddr,
    ) -> Result<(), Error> {
        let (tx, _rx) = unbounded::<NetlinkMessage>();
        let request = Request::from((tx, message, destination));
        debug!("handle: forwarding new request to connection");
        UnboundedSender::unbounded_send(&self.requests_tx, request)
            .map_err(|_| ErrorKind::ConnectionClosed.into())
    }
}
