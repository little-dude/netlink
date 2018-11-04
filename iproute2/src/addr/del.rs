use futures::{stream, Async, Future, Poll, Stream};

use rtnetlink::constants::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use rtnetlink::{AddressMessage, NetlinkFlags, NetlinkMessage, RtnlMessage};

use connection::ConnectionHandle;
use errors::NetlinkIpError;

use Stream2Ack;

lazy_static! {
    // Flags for `ip addr del`
    static ref DEL_FLAGS: NetlinkFlags =
        NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct AddressDelRequest {
    handle: ConnectionHandle,
    messages: Vec<AddressMessage>,
}

impl AddressDelRequest {
    pub(crate) fn new(handle: ConnectionHandle, messages: Vec<AddressMessage>) -> Self {
        AddressDelRequest { handle, messages }
    }
}

pub struct AddressDelRequestFuture<T>(pub(crate) T);

impl<T> Future for AddressDelRequestFuture<T>
where
    T: Future<Item = AddressDelRequest>,
    NetlinkIpError: ::std::convert::From<<T as ::futures::Future>::Error>,
{
    type Item = AddressDelRequest;
    type Error = NetlinkIpError;

    fn poll(&mut self) -> Poll<Self::Item, NetlinkIpError> {
        let value = try_ready!(self.0.poll());
        Ok(Async::Ready(value))
    }
}

impl<T> AddressDelRequestFuture<T>
where
    T: Future<Item = AddressDelRequest>,
    NetlinkIpError: ::std::convert::From<<T as ::futures::Future>::Error>,
{
    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = NetlinkIpError> {
        self.and_then(|s| {
            let mut handle = s.handle;
            let reqs = stream::iter_ok(s.messages)
                .map(move |message| {
                    let mut req = NetlinkMessage::from(RtnlMessage::DelAddress(message));
                    req.header_mut().set_flags(*DEL_FLAGS);
                    handle.request(req)
                }).flatten();
            Stream2Ack::new(reqs)
        })
    }
}
