use errors::Error;
use futures::{Async, Future, Poll, Stream};
use packets::NetlinkMessage;
use std::mem;


pub(crate) struct Stream2Ack<S>(S);

impl<S> Stream2Ack<S> {
    pub(crate) fn new(s: S) -> Self {
        Stream2Ack(s)
    }
}

impl<S> Future for Stream2Ack<S>
where
    S: Stream<Item = NetlinkMessage, Error = Error>,
{
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll()? {
            Async::NotReady => Ok(Async::NotReady),
            // If the stream closes right away, that means we received an ack
            Async::Ready(None) => Ok(Async::Ready(())),
            Async::Ready(Some(msg)) => {
                if msg.is_error() {
                    Err(NetlinkPacketError::NetlinkError(msg.clone()))
                } else {
                    Err(NetlinkPacketError::NetlinkError(msg))
                }
            }
        }
    }
}
