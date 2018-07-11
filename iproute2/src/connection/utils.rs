use errors::NetlinkIpError;
use futures::{Async, Future, Poll, Stream};
use rtnetlink::NetlinkMessage;
use std::mem;

/// A future that polls a `Stream` until the end, and return all the items in a `Vec`
pub(crate) struct Stream2Vec<S, T>(S, Option<Vec<T>>);

impl<S, T> Stream2Vec<S, T> {
    pub(crate) fn new(s: S) -> Self {
        Stream2Vec(s, Some(vec![]))
    }
}

impl<S: Stream<Item = Result<T, NetlinkIpError>, Error = NetlinkIpError>, T> Future
    for Stream2Vec<S, T>
{
    type Item = Vec<T>;
    type Error = NetlinkIpError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        trace!("polling Stream2Vec");
        loop {
            match self.0.poll()? {
                Async::Ready(Some(item)) => self.1.as_mut().unwrap().push(item?),
                Async::Ready(None) => {
                    trace!("Stream2Vec: end of stream");
                    return Ok(Async::Ready(mem::replace(&mut self.1, None).unwrap()));
                }
                Async::NotReady => {
                    trace!("Stream2Vec: not ready");
                    return Ok(Async::NotReady);
                }
            }
        }
    }
}

pub(crate) struct Stream2Ack<S>(S);

impl<S> Stream2Ack<S> {
    pub(crate) fn new(s: S) -> Self {
        Stream2Ack(s)
    }
}

impl<S> Future for Stream2Ack<S>
where
    S: Stream<Item = NetlinkMessage, Error = NetlinkIpError>,
{
    type Item = ();
    type Error = NetlinkIpError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll()? {
            Async::NotReady => Ok(Async::NotReady),
            // If the stream closes right away, that means we received an ack
            Async::Ready(None) => Ok(Async::Ready(())),
            Async::Ready(Some(msg)) => {
                if msg.is_error() {
                    Err(NetlinkIpError::NetlinkError(msg.clone()))
                } else {
                    Err(NetlinkIpError::NetlinkError(msg))
                }
            }
        }
    }
}
