// SPDX-License-Identifier: MIT

use bytes::BytesMut;
use std::{
    fmt::Debug,
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use log::error;

use crate::{
    codecs::NetlinkMessageCodec,
    sys::{AsyncSocket, SocketAddr},
};
use netlink_packet_core::{NetlinkDeserializable, NetlinkMessage, NetlinkSerializable};

// some functions don't need the message type and codec type
struct FramedIO<S> {
    socket: S,
    reader: BytesMut,
    writer: BytesMut,
    in_addr: SocketAddr,
    out_addr: SocketAddr,
    flushed: bool,
}

impl<S> FramedIO<S>
where
    S: AsyncSocket,
{
    fn poll_next_datagram(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        self.reader.clear();
        self.reader.reserve(INITIAL_READER_CAPACITY);

        self.in_addr = match ready!(self.socket.poll_recv_from(cx, &mut self.reader)) {
            Ok(addr) => addr,
            Err(e) => {
                error!("failed to read from netlink socket: {:?}", e);
                return Poll::Ready(Err(()));
            }
        };
        Poll::Ready(Ok(()))
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        trace!("flushing frame; length={}", self.writer.len());
        let Self {
            ref mut socket,
            ref mut out_addr,
            ref mut writer,
            ..
        } = *self;

        let n = ready!(socket.poll_send_to(cx, writer, out_addr))?;
        trace!("written {}", n);

        let wrote_all = n == self.writer.len();
        self.writer.clear();
        self.flushed = true;

        let res = if wrote_all {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to write entire datagram to socket",
            ))
        };

        Poll::Ready(res)
    }
}

pub struct NetlinkFramed<T, S, C> {
    io: FramedIO<S>,
    // see https://doc.rust-lang.org/nomicon/phantom-data.html
    // "invariant" seems like the safe choice; using `fn(T) -> T`
    // should make it invariant but still Send+Sync.
    msg_type: PhantomData<fn(T) -> T>, // invariant
    codec: PhantomData<fn(C) -> C>,    // invariant
}

impl<T, S, C> Stream for NetlinkFramed<T, S, C>
where
    T: NetlinkDeserializable + Debug,
    S: AsyncSocket,
    C: NetlinkMessageCodec,
{
    type Item = (NetlinkMessage<T>, SocketAddr);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self { ref mut io, .. } = Pin::get_mut(self);

        loop {
            match C::decode::<T>(&mut io.reader) {
                Ok(Some(item)) => return Poll::Ready(Some((item, io.in_addr))),
                Ok(None) => {}
                Err(e) => {
                    error!("unrecoverable error in decoder: {:?}", e);
                    return Poll::Ready(None);
                }
            }

            if let Err(()) = ready!(io.poll_next_datagram(cx)) {
                return Poll::Ready(None);
            }
        }
    }
}

impl<T, S, C> Sink<(NetlinkMessage<T>, SocketAddr)> for NetlinkFramed<T, S, C>
where
    T: NetlinkSerializable + Debug,
    S: AsyncSocket,
    C: NetlinkMessageCodec,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.io.poll_ready(cx)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: (NetlinkMessage<T>, SocketAddr),
    ) -> Result<(), Self::Error> {
        trace!("sending frame");
        let (frame, out_addr) = item;
        let pin = self.get_mut();
        C::encode(frame, &mut pin.io.writer)?;
        pin.io.out_addr = out_addr;
        pin.io.flushed = false;
        trace!("frame encoded; length={}", pin.io.writer.len());
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.io.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.io.poll_flush(cx)
    }
}

// The theoritical max netlink packet size is 32KB for a netlink
// message since Linux 4.9 (16KB before). See:
// https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/commit/?id=d35c99ff77ecb2eb239731b799386f3b3637a31e
const INITIAL_READER_CAPACITY: usize = 64 * 1024;
const INITIAL_WRITER_CAPACITY: usize = 8 * 1024;

impl<T, S, C> NetlinkFramed<T, S, C> {
    /// Create a new `NetlinkFramed` backed by the given socket and codec.
    ///
    /// See struct level documentation for more details.
    pub fn new(socket: S) -> Self {
        Self {
            io: FramedIO {
                socket,
                out_addr: SocketAddr::new(0, 0),
                in_addr: SocketAddr::new(0, 0),
                reader: BytesMut::with_capacity(INITIAL_READER_CAPACITY),
                writer: BytesMut::with_capacity(INITIAL_WRITER_CAPACITY),
                flushed: true,
            },
            msg_type: PhantomData,
            codec: PhantomData,
        }
    }

    /// Returns a reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_ref(&self) -> &S {
        &self.io.socket
    }

    /// Returns a mutable reference to the underlying I/O stream wrapped by
    /// `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io.socket
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    pub fn into_inner(self) -> S {
        self.io.socket
    }
}
