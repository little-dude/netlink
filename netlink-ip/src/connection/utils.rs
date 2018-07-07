use errors::NetlinkIpError;
use futures::{Async, Future, Poll, Stream};
use std::mem;

/// A future that polls a `Stream` until the end, and return all the items in a `Vec`
pub(crate) struct FutureVec<S, T>(S, Option<Vec<T>>);

impl<S, T> FutureVec<S, T> {
    pub(crate) fn new(s: S) -> Self {
        FutureVec(s, Some(vec![]))
    }
}

impl<S: Stream<Item = Result<T, NetlinkIpError>, Error = NetlinkIpError>, T> Future
    for FutureVec<S, T>
{
    type Item = Vec<T>;
    type Error = NetlinkIpError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        trace!("polling FutureVec");
        loop {
            match self.0.poll()? {
                Async::Ready(Some(item)) => self.1.as_mut().unwrap().push(item?),
                Async::Ready(None) => {
                    trace!("FutureVec: end of stream");
                    return Ok(Async::Ready(mem::replace(&mut self.1, None).unwrap()));
                }
                Async::NotReady => {
                    trace!("FutureVec: not ready");
                    return Ok(Async::NotReady);
                }
            }
        }
    }
}
