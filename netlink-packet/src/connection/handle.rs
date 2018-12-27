use errors::Error;
use futures::sync::mpsc::{unbounded, UnboundedSender};
use futures::Stream;
use packets::NetlinkMessage;

type RequestsTx = UnboundedSender<(UnboundedSender<NetlinkMessage>, NetlinkMessage)>;

/// A handle to pass requests to a [`Connection`](struct.Connection.html).
#[derive(Clone, Debug)]
pub struct ConnectionHandle {
    requests_tx: UnboundedSender<(UnboundedSender<NetlinkMessage>, NetlinkMessage)>,
}

impl ConnectionHandle {
    pub(crate) fn new(requests_tx: RequestsTx) -> Self {
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
    ) -> impl Stream<Item = NetlinkMessage, Error = Error> {
        let (tx, rx) = unbounded::<NetlinkMessage>();
        // Ignore the result. If this failed, `tx` will be dropped when this funtion returns, and
        // polling rx with fail, carrying the error.
        debug!("handle: forwarding new request to connection");
        let _ = UnboundedSender::unbounded_send(&self.requests_tx, (tx, message));
        rx.map_err(|()| {
            error!("could not forward new request to connection: the connection is closed");
            NetlinkPacketError::ConnectionClosed
        })
    }
}
