use std::collections::HashMap;
use std::io;

use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{Async, AsyncSink, Future, Poll, Sink, Stream};

use netlink_packet::NetlinkMessage;
use netlink_sys::{Protocol, SocketAddr, TokioSocket};
use std::collections::VecDeque;

use crate::errors::{Error, ErrorKind};

use super::codecs::NetlinkCodec;
use super::framed::NetlinkFramed;
use super::request::Request;

lazy_static! {
    static ref KERNEL_UNICAST: SocketAddr = SocketAddr::new(0, 0);
}

/// Connection to a netlink socket, running in the background.
///
/// [`ConnectionHandle`](struct.ConnectionHandle.html) are used to pass new requests to the
/// `Connection`, that in turn, sends them through the netlink socket.
pub struct Connection {
    socket: NetlinkFramed<NetlinkCodec<NetlinkMessage>>,

    // Counter that is incremented for each message sent
    sequence_id: u32,

    // Requests for which we're waiting for a response
    pending_requests: HashMap<(SocketAddr, u32), UnboundedSender<NetlinkMessage>>,

    // Requests to be sent out
    requests_buffer: VecDeque<Request>,

    // Channel used by the user to pass requests to the connection. These requests are either sent
    // out as soon as they are received, or put in self.requests_buffer for and processed later.
    requests_rx: UnboundedReceiver<Request>,

    // Channel used to transmit to the ConnectionHandle the unsollicited messages received from the
    // socket (multicast messages for instance).
    incoming_messages_tx: UnboundedSender<NetlinkMessage>,

    // Indicate whether this connection is shutting down.
    shutting_down: bool,
}

impl Connection {
    pub(crate) fn new(
        requests_rx: UnboundedReceiver<Request>,
        incoming_messages_tx: UnboundedSender<NetlinkMessage>,
        protocol: Protocol,
    ) -> io::Result<Self> {
        let socket = TokioSocket::new(protocol)?;
        Ok(Connection {
            socket: NetlinkFramed::new(socket, NetlinkCodec::<NetlinkMessage>::new()),
            sequence_id: 0,
            pending_requests: HashMap::new(),
            requests_buffer: VecDeque::with_capacity(1024),
            requests_rx,
            shutting_down: false,
            incoming_messages_tx,
        })
    }

    pub fn socket_mut(&mut self) -> &mut TokioSocket {
        self.socket.get_mut()
    }

    fn prepare_message(&mut self, message: &mut NetlinkMessage) {
        self.sequence_id += 1;
        message.header_mut().set_sequence_number(self.sequence_id);
        message.finalize();
    }

    // FIXME: this should return an error when the sink is full and we don't have any more
    // space to buffer the message
    fn send(&mut self, request: Request) -> AsyncSink<Request> {
        if !self.requests_buffer.is_empty() {
            trace!("there are already requests waiting for being sent");
            return AsyncSink::NotReady(request);
        }

        let (tx, message, destination) = request.into();
        trace!("sending message: {:?} to {:?}", message, destination);
        match self.socket.start_send((message, destination)).unwrap() {
            AsyncSink::NotReady((message, destination)) => {
                // The sink is full atm. There is no need to try to call poll_send() because
                // internally start_send should call it:
                //
                //     https://docs.rs/tokio/0.1.7/tokio/prelude/trait.Sink.html#tymethod.start_send
                //
                //     The method returns AsyncSink::NotReady if the sink was unable to begin
                //     sending, usually due to being full. The sink must have attempted to complete
                //     processing any outstanding requests (equivalent to poll_complete) before
                //     yielding this result.
                trace!("the sink is full, cannot send the message now");
                AsyncSink::NotReady((tx, message, destination).into())
            }
            AsyncSink::Ready => {
                trace!("message sent!");
                // NetlinkFramed can only buffer one frame, so to avoid clogging the sink, we need
                // to flush it as soon as we call start_send(). We don't care about the result
                // however.
                let _ = self.socket.poll_complete().unwrap();
                // Return Ready, because the message is being sent
                AsyncSink::Ready
            }
        }
    }

    fn process_buffered_requests(&mut self) {
        while let Some(request) = self.requests_buffer.pop_front() {
            match self.send(request) {
                AsyncSink::Ready => {}
                AsyncSink::NotReady(request) => {
                    self.requests_buffer.push_front(request);
                    return;
                }
            }
        }
        trace!("all the buffered requests have been sent");
    }

    fn handle_message(&mut self, message: NetlinkMessage, source: SocketAddr) {
        let seq = message.header().sequence_number();
        let mut close_chan = false;

        debug!("handling message {}", seq);

        if let Some(tx) = self.pending_requests.get_mut(&(source, seq)) {
            if !message.header().flags().has_multipart() {
                trace!("not a multipart message");
                close_chan = true;
            }

            if message.is_done() {
                trace!("received end of dump message");
                close_chan = true;
            } else if message.is_noop() {
                trace!("ignoring NOOP");
            } else if message.is_error() {
                trace!("forwarding error message and closing channel with handle");
                // If send returns an Err, its because the other side has been dropped, so it
                // does not really matter.
                let _ = tx.unbounded_send(message);
                close_chan = true;
            } else if message.is_ack() {
                trace!("got ack for message {}", message.header().sequence_number());
                // FIXME: we could set `close_chan = true` and not forward the ACK to the handle,
                // if we assume receiving an ACK means we won't receive other messages for that
                // request. But I'm not sure whether that's the case.
                //
                // close_chan = true;
                let _ = tx.unbounded_send(message);
            } else if message.is_overrun() {
                // FIXME: we should obviously NOT panic here but I'm not sure what we
                // should do. Can we increase the buffer size now? Should we leave that the
                // users?
                panic!("overrun: receive buffer is full");
            } else {
                let _ = tx.unbounded_send(message);
            }
        } else {
            let _ = self.incoming_messages_tx.unbounded_send(message);
        }

        if close_chan {
            debug!("removing {} from the pending requests", seq);
            let _ = self.pending_requests.remove(&(source, seq));
        }
    }

    fn read_all(&mut self) -> Result<(), Error> {
        trace!("reading from socket");
        loop {
            match self
                .socket
                .poll()
                .map_err(|e| Error::from(ErrorKind::SocketIo(e)))?
            {
                Async::Ready(Some((message, source))) => {
                    trace!("message received: {:?}", message);
                    self.handle_message(message, source);
                }
                Async::Ready(None) => {
                    trace!("socket closed");
                    return Err(ErrorKind::ConnectionClosed.into());
                }
                Async::NotReady => return Ok(()),
            }
        }
    }

    fn process_requests(&mut self) {
        trace!("polling the requests channel");
        // FIXME: this fails if the request channel is closed, which can be the case, for instance
        // for read-only connections, where there's no need for requests.
        while let Async::Ready(item) = self.requests_rx.poll().unwrap() {
            if let Some(mut request) = item {
                trace!("request received, sending it through the netlink socket");
                self.prepare_message(&mut request.message);
                let destination = request.destination;
                let response_chan = request.chan.clone();
                // NOTE: one send returns NotReady, it will keep returning NotReady for the
                // rest of the requests, so they will all be buffered.
                match self.send(request) {
                    AsyncSink::Ready => {
                        self.pending_requests
                            .insert((destination, self.sequence_id), response_chan);
                    }
                    AsyncSink::NotReady(request) => {
                        trace!("buffering the request");
                        self.requests_buffer.push_back(request);
                    }
                }
            } else {
                trace!("requests channel is closed");
                self.shutdown();
                break;
            }
        }
    }

    fn shutdown(&mut self) {
        debug!("shutting down the connection");
        self.requests_rx.close();
        self.shutting_down = true;
    }
}

impl Future for Connection {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        debug!("polling connection");
        if let Err(e) = self.read_all() {
            match e.kind() {
                ErrorKind::ConnectionClosed => return Ok(Async::Ready(())),
                _ => return Err(e),
            }
        }

        trace!("flushing socket");
        if let Async::NotReady = self.socket.poll_complete().unwrap() {
            // We do not poll the requests channel if the sink is full to create backpressure. It's
            // ok not to poll because as soon as the sink makes progress, this future will be
            // called.
            trace!("socket is still busy sending messages: the connection will be polled again when progress has been made");
            return Ok(Async::NotReady);
        }

        self.process_buffered_requests();
        if !self.requests_buffer.is_empty() {
            trace!("there are requests waiting to be sent. Not processing any new request for now");
            return Ok(Async::NotReady);
        }

        if self.shutting_down {
            // If we're shutting down, we don't accept any more request
            trace!("the connection is shutting down: not trying to get new requests");
            return Ok(Async::NotReady);
        }

        self.process_requests();

        // After sending the requests, flush the sink. We don't care about the outcome here
        trace!("flushing outgoing messages");
        let _ = self.socket.poll_complete().unwrap();

        trace!("re-registering interest in readiness events for the connection");
        Ok(Async::NotReady)
    }
}
