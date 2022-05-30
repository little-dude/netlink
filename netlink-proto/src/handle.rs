// SPDX-License-Identifier: MIT

use futures::{
    channel::mpsc::{unbounded, UnboundedSender},
    Stream,
};
use netlink_packet_core::NetlinkMessage;
use std::fmt::Debug;

use crate::{errors::Error, sys::SocketAddr, Request};

/// A handle to pass requests to a [`Connection`](struct.Connection.html).
#[derive(Debug)]
pub struct ConnectionHandle<T>
where
    T: Debug,
{
    requests_tx: UnboundedSender<Request<T>>,
}

impl<T> ConnectionHandle<T>
where
    T: Debug,
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
    ) -> Result<impl Stream<Item = NetlinkMessage<T>>, Error<T>> {
        let (tx, rx) = unbounded::<NetlinkMessage<T>>();
        let request = Request::Single {
            message,
            destination,
            metadata: tx,
        };
        debug!("handle: forwarding new request to connection");
        UnboundedSender::unbounded_send(&self.requests_tx, request).map_err(|e| {
            // the channel is unbounded, so it can't be full. If this
            // failed, it means the Connection shut down.
            if e.is_full() {
                panic!("internal error: unbounded channel full?!");
            } else if e.is_disconnected() {
                Error::ConnectionClosed
            } else {
                panic!("unknown error: {:?}", e);
            }
        })?;
        Ok(rx)
    }

    /// Start a batch of messages
    ///
    /// Collects multiple messages to be sent in one "request".
    pub fn batch(&self, destination: SocketAddr) -> BatchHandle<T> {
        BatchHandle {
            handle: self.clone(),
            destination,
            messages: Vec::new(),
            channels: Vec::new(),
        }
    }

    pub fn notify(
        &mut self,
        message: NetlinkMessage<T>,
        destination: SocketAddr,
    ) -> Result<(), Error<T>> {
        let (tx, _rx) = unbounded::<NetlinkMessage<T>>();
        let request = Request::Single {
            message,
            destination,
            metadata: tx,
        };
        debug!("handle: forwarding new request to connection");
        UnboundedSender::unbounded_send(&self.requests_tx, request)
            .map_err(|_| Error::ConnectionClosed)
    }
}

// don't want to require `T: Clone`, so can't derive it
impl<T: Debug> Clone for ConnectionHandle<T> {
    fn clone(&self) -> Self {
        Self {
            requests_tx: self.requests_tx.clone(),
        }
    }
}

/// A handle to create a batch request (multiple requests serialized in one buffer)
///
/// The request needs to be [`sent`](`BatchHandle::send`) to actually do something.
#[derive(Debug)]
#[must_use = "A batch of messages must be sent to actually do something"]
pub struct BatchHandle<T>
where
    T: Debug,
{
    handle: ConnectionHandle<T>,
    destination: SocketAddr,
    messages: Vec<NetlinkMessage<T>>,
    channels: Vec<UnboundedSender<NetlinkMessage<T>>>,
}

impl<T> BatchHandle<T>
where
    T: Debug,
{
    /// Add a new request to the batch and get the response as a stream of messages.
    ///
    /// Similar to [`ConnectionHandle::request`].
    ///
    /// Response stream will block until batch request is sent, and will be empty
    /// if the batch request is dropped.
    pub fn request(&mut self, message: NetlinkMessage<T>) -> impl Stream<Item = NetlinkMessage<T>> {
        let (tx, rx) = unbounded::<NetlinkMessage<T>>();
        self.messages.push(message);
        self.channels.push(tx);
        rx
    }

    /// Add a new request to the batch, but ignore response messages
    ///
    /// Similar to [`ConnectionHandle::notify`].
    pub fn notify(&mut self, message: NetlinkMessage<T>) {
        let _ = self.request(message);
    }

    /// Send batch request
    pub fn send(self) -> Result<(), Error<T>> {
        debug!("handle: forwarding new request to connection");
        let request = Request::Batch {
            metadata: self.channels,
            messages: self.messages,
            destination: self.destination,
        };
        UnboundedSender::unbounded_send(&self.handle.requests_tx, request).map_err(|e| {
            // the channel is unbounded, so it can't be full. If this
            // failed, it means the Connection shut down.
            if e.is_full() {
                panic!("internal error: unbounded channel full?!");
            } else if e.is_disconnected() {
                Error::ConnectionClosed
            } else {
                panic!("unknown error: {:?}", e);
            }
        })?;
        Ok(())
    }
}
