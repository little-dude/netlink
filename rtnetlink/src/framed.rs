use std::io;
use tokio_io::codec::{Decoder, Encoder};

use bytes::{BufMut, BytesMut};
use futures::{Async, AsyncSink, Poll, Sink, StartSend, Stream};
use netlink_socket::{SocketAddr, TokioSocket};

pub struct NetlinkFramed<C> {
    socket: TokioSocket,
    codec: C,
    reader: BytesMut,
    writer: BytesMut,
    out_addr: SocketAddr,
    in_addr: SocketAddr,
    flushed: bool,
}

impl<C: Decoder> Stream for NetlinkFramed<C> {
    type Item = (C::Item, SocketAddr);
    type Error = C::Error;

    fn poll(&mut self) -> Poll<Option<(Self::Item)>, Self::Error> {
        if let Some(item) = self.codec.decode(&mut self.reader)? {
            return Ok(Async::Ready(Some((item, self.in_addr))));
        }

        // There should not be byte left in the buffer. NetlinkMessage oriented protocols guarantee that
        // complete datagrams are being delivered.
        if !self.reader.is_empty() {
            error!(
                "{} bytes left in the buffer that could not be decoded",
                self.reader.len()
            );
        }

        self.reader.clear();
        self.reader.reserve(INITIAL_READER_CAPACITY);

        self.in_addr = unsafe {
            // Read into the buffer without having to initialize the memory.
            let (n, addr) = try_ready!(self.socket.poll_recv_from(self.reader.bytes_mut()));
            self.reader.advance_mut(n);
            addr
        };

        if let Some(item) = self.codec.decode(&mut self.reader)? {
            return Ok(Async::Ready(Some((item, self.in_addr))));
        } else {
            // FIXME: I think that is impossible, unless 0 bytes were read.
            //
            // But then we would have returned NotReady I think?
            //
            // Or does this means EOF? But if it's EOF, we should already have return an io::Err
            // in try_ready! no?
            panic!("I'm not sure how to handle this")
        }
    }
}

impl<C: Encoder> Sink for NetlinkFramed<C> {
    type SinkItem = (C::Item, SocketAddr);
    type SinkError = C::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        trace!("sending frame");

        if !self.flushed {
            trace!("flushing the sink, before sending the frame");
            match self.poll_complete()? {
                Async::Ready(()) => trace!("sink flushed"),
                Async::NotReady => {
                    trace!("could not flush the sink entirely");
                    return Ok(AsyncSink::NotReady(item));
                }
            }
        }

        let (frame, out_addr) = item;
        self.codec.encode(frame, &mut self.writer)?;
        self.out_addr = out_addr;
        self.flushed = false;
        trace!("frame encoded; length={}", self.writer.len());

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), C::Error> {
        if self.flushed {
            return Ok(Async::Ready(()));
        }

        trace!("flushing frame; length={}", self.writer.len());
        let n = try_ready!(self.socket.poll_send_to(&self.writer, &self.out_addr));
        trace!("written {}", n);

        let wrote_all = n == self.writer.len();
        self.writer.clear();
        self.flushed = true;

        if wrote_all {
            Ok(Async::Ready(()))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to write entire datagram to socket",
            ).into())
        }
    }

    fn close(&mut self) -> Poll<(), C::Error> {
        try_ready!(self.poll_complete());
        Ok(().into())
    }
}

const INITIAL_READER_CAPACITY: usize = 64 * 1024;
const INITIAL_WRITER_CAPACITY: usize = 8 * 1024;

impl<C> NetlinkFramed<C> {
    /// Create a new `NetlinkFramed` backed by the given socket and codec.
    ///
    /// See struct level documentation for more details.
    pub fn new(socket: TokioSocket, codec: C) -> NetlinkFramed<C> {
        NetlinkFramed {
            socket,
            codec,
            out_addr: SocketAddr::new(0, 0),
            in_addr: SocketAddr::new(0, 0),
            reader: BytesMut::with_capacity(INITIAL_READER_CAPACITY),
            writer: BytesMut::with_capacity(INITIAL_WRITER_CAPACITY),
            flushed: true,
        }
    }

    /// Returns a reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_ref(&self) -> &TokioSocket {
        &self.socket
    }

    /// Returns a mutable reference to the underlying I/O stream wrapped by
    /// `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_mut(&mut self) -> &mut TokioSocket {
        &mut self.socket
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    pub fn into_inner(self) -> TokioSocket {
        self.socket
    }
}
