use std::collections::HashMap;
use std::io;

use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Sink, Stream};

use netlink_sys::rtnl::Message;
use netlink_sys::{NetlinkCodec, NetlinkFramed, Protocol, SocketAddr, TokioSocket};

type RequestsRx = UnboundedReceiver<(UnboundedSender<Message>, Message)>;

lazy_static! {
    static ref KERNEL_PORT: SocketAddr = SocketAddr::new(0, 0);
}

pub struct Connection {
    socket: NetlinkFramed<NetlinkCodec<Message>>,
    sequence_id: u32,
    pending_requests: HashMap<u32, UnboundedSender<Message>>,
    requests_rx: RequestsRx,
    shutting_down: bool,
}

impl Connection {
    pub(crate) fn new(requests_rx: RequestsRx) -> io::Result<Self> {
        let socket = TokioSocket::new(Protocol::Route)?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Connection {
            socket: NetlinkFramed::new(socket, NetlinkCodec::<Message>::new()),
            sequence_id: 0,
            pending_requests: HashMap::new(),
            requests_rx,
            shutting_down: false,
        })
    }

    fn send_request(&mut self, mut message: Message) -> u32 {
        self.sequence_id += 1;
        message.set_sequence_number(self.sequence_id);
        message.finalize();
        // FIXME: in futures 0.2, use poll_ready before reading from pending_responses, and
        // don't panic here.
        self.socket.start_send((message, *KERNEL_PORT)).unwrap();
        self.sequence_id
    }

    fn handle_message(&mut self, message: Message) {
        let seq = message.sequence_number();
        let mut close_chan = false;

        if let Some(tx) = self.pending_requests.get_mut(&seq) {
            if ! message.flags().has_multipart() {
                trace!("not a multipart message");
                close_chan = true;
            }

            if message.is_done() {
                trace!("received end of dump message");
                close_chan = true;
            } else if message.is_noop() {
                trace!("ignoring NOOP");
            } else if message.is_error() {
                //
                // FIXME: handle ack! They are special errors!
                //
                trace!("forwarding error message and closing channel with handle");
                // If send returns an Err, its because the other side has been dropped, so it
                // does not really matter.
                let _ = UnboundedSender::unbounded_send(tx, message);
                close_chan = true;
            } else if message.is_overrun() {
                // FIXME: we should obviously NOT panic here but I'm not sure what we
                // should do. Can we increase the buffer size now? Should we leave that the
                // users?
                panic!("overrun: receive buffer is full");
            }
        } else {
            // FIXME: we should check whether it's an Overrun error maybe?
            trace!(
                "unknown sequence number {}, ignoring the message",
                message.sequence_number()
            );
        }

        if close_chan {
            let _ = self.pending_requests.remove(&seq);
        }
    }

    fn shutdown(&mut self) {
        self.requests_rx.close();
        self.shutting_down = true;
    }
}

impl Future for Connection {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        trace!("polling socket");

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

        if let Async::NotReady = self.socket.poll_complete().unwrap() {
            // We do not poll the requests channel if the sink is full to create backpressure. It's
            // ok not to poll because as soon as the sink makes progress, this future will be
            // called.
            return Ok(Async::NotReady);
        }

        if self.shutting_down {
            // If we're shutting down, we don't accept any more request
            return Ok(Async::NotReady);
        }

        trace!("polling requests channel");
        while let Async::Ready(request) = self.requests_rx.poll().unwrap() {
            if let Some((tx_channel, msg)) = request {
                trace!("request received");
                let seq = self.send_request(msg);
                self.pending_requests.insert(seq, tx_channel);
            } else {
                trace!("requests channel is closed");
                self.shutdown();
            }
        }

        Ok(Async::NotReady)
    }
}
