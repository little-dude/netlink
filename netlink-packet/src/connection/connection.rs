use std::collections::HashMap;
use std::io;

use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{Async, AsyncSink, Future, Poll, Sink, Stream};

use netlink_sys::{Protocol, SocketAddr, TokioSocket};
use std::collections::VecDeque;
use {NetlinkMessage, Result};

use super::codecs::NetlinkCodec;
use super::framed::NetlinkFramed;

type RequestsRx = UnboundedReceiver<(UnboundedSender<NetlinkMessage>, NetlinkMessage)>;

lazy_static! {
    static ref KERNEL_PORT: SocketAddr = SocketAddr::new(0, 0);
}

/// Connection to a netlink socket, running in the background.
///
/// [`ConnectionHandle`](struct.ConnectionHandle.html) are used to pass new requests to the
/// `Connection`, that in turn, sends them through the netlink socket.
pub struct Connection {
    socket: NetlinkFramed<NetlinkCodec<NetlinkMessage>>,
    sequence_id: u32,
    // This is kind of hacky, and due to an implementation detail of NetlinkFramed.
    // Basically, the Sink API assumes that multiple `start_send()` calls can be done before
    // calling `poll_complete()`, and that the items being sent will be buffered. But NetlinkFramed
    // only buffers one frame, so subsequent calls to `
    requests_buffer: VecDeque<NetlinkMessage>,
    pending_requests: HashMap<u32, UnboundedSender<NetlinkMessage>>,
    requests_rx: RequestsRx,
    shutting_down: bool,
}

impl Connection {
    pub(crate) fn new(requests_rx: RequestsRx) -> io::Result<Self> {
        let socket = TokioSocket::new(Protocol::Route)?;
        trace!("socket: connecting");
        socket.connect(&KERNEL_PORT)?;
        Ok(Connection {
            socket: NetlinkFramed::new(socket, NetlinkCodec::<NetlinkMessage>::new()),
            sequence_id: 0,
            pending_requests: HashMap::new(),
            requests_buffer: VecDeque::with_capacity(1024),
            requests_rx,
            shutting_down: false,
        })
    }

    fn prepare_request(&mut self, message: &mut NetlinkMessage) {
        self.sequence_id += 1;
        message.header_mut().set_sequence_number(self.sequence_id);
        message.finalize();
    }

    // FIXME: this should probably return an error when the sink is full and we don't have any more
    // space to buffer the message
    fn send_request(&mut self, message: NetlinkMessage) -> AsyncSink<NetlinkMessage> {
        if !self.requests_buffer.is_empty() {
            trace!("there are already requests waiting for being sent");
            return AsyncSink::NotReady(message);
        }

        // FIXME: in futures 0.2, use poll_ready before reading from pending_responses, and
        // don't panic here.
        trace!("sending message: {:?}", message);
        match self.socket.start_send((message, *KERNEL_PORT)).unwrap() {
            AsyncSink::NotReady((message, _)) => {
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
                AsyncSink::NotReady(message)
            }
            AsyncSink::Ready => {
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
        while let Some(message) = self.requests_buffer.pop_front() {
            match self.send_request(message) {
                AsyncSink::Ready => {}
                AsyncSink::NotReady(message) => {
                    self.requests_buffer.push_front(message);
                    return;
                }
            }
        }
        trace!("all the buffered requests have been sent");
    }

    fn buffer_request(&mut self, request: NetlinkMessage) -> Result<()> {
        if self.requests_buffer.len() == self.requests_buffer.capacity() {
            // we should drop the request and return an error
            unimplemented!()
        }
        self.requests_buffer.push_back(request);
        Ok(())
    }

    fn handle_message(&mut self, message: NetlinkMessage) {
        let seq = message.header().sequence_number();
        let mut close_chan = false;

        debug!("handling message {}", seq);

        if let Some(tx) = self.pending_requests.get_mut(&seq) {
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
                let _ = UnboundedSender::unbounded_send(tx, message);
                close_chan = true;
            } else if message.is_ack() {
                trace!(
                    "received ack for message {}",
                    message.header().sequence_number()
                );
                close_chan = true;
            } else if message.is_overrun() {
                // FIXME: we should obviously NOT panic here but I'm not sure what we
                // should do. Can we increase the buffer size now? Should we leave that the
                // users?
                panic!("overrun: receive buffer is full");
            } else {
                tx.unbounded_send(message).expect("FIXME: handle that");
            }
        } else {
            // FIXME: we should check whether it's an Overrun error maybe?
            trace!(
                "unknown sequence number {}, ignoring the message",
                message.header().sequence_number()
            );
        }

        if close_chan {
            debug!("removing {} from the pending requests", seq);
            let _ = self.pending_requests.remove(&seq);
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
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        debug!("polling connection");

        trace!("reading from socket");
        while let Async::Ready(msg) = self.socket.poll().unwrap() {
            if let Some((msg, _addr)) = msg {
                trace!("message received: {:?}", msg);
                self.handle_message(msg);
            } else {
                trace!("socket closed");
                // XXX: check if there's something else to do?
                return Ok(Async::Ready(()));
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

        trace!("polling requests channel");
        while let Async::Ready(request) = self.requests_rx.poll().unwrap() {
            if let Some((tx_channel, mut msg)) = request {
                trace!("request received");
                self.prepare_request(&mut msg);
                match self.send_request(msg) {
                    AsyncSink::Ready => {
                        trace!("request sent with sequence id {}", self.sequence_id);
                        self.pending_requests.insert(self.sequence_id, tx_channel);
                    }
                    AsyncSink::NotReady(msg) => {
                        trace!("buffering message that could not be sent");
                        self.buffer_request(msg).unwrap();
                    }
                }
            } else {
                trace!("requests channel is closed");
                self.shutdown();
                break;
            }
        }

        // After sending the requests, flush the sink. We don't care about the outcome here
        let _ = self.socket.poll_complete().unwrap();

        trace!("re-registering interest in readiness events for the connection");
        Ok(Async::NotReady)
    }
}
