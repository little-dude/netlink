use futures::sync::mpsc::{unbounded, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use link::{Link, LinkData};
use netlink_sys::rtnl::{LinkFlags, LinkHeader, LinkLayerType, LinkMessage, Message, RtnlMessage};
use netlink_sys::{constants, NetlinkFlags};
use std::mem;

use errors::NetlinkIpError;

type RequestsTx = UnboundedSender<(UnboundedSender<Message>, Message)>;

#[derive(Clone, Debug)]
pub struct ConnectionHandle {
    requests_tx: UnboundedSender<(UnboundedSender<Message>, Message)>,
}

impl ConnectionHandle {
    pub(crate) fn new(requests_tx: RequestsTx) -> Self {
        ConnectionHandle { requests_tx }
    }

    pub fn request(
        &mut self,
        message: Message,
    ) -> impl Stream<Item = Message, Error = NetlinkIpError> {
        let (tx, rx) = unbounded::<Message>();
        // Ignore the result. If this failed, `tx` will be dropped when this fcuntion returns, and
        // polling rx with fail, carrying the error.
        let _ = UnboundedSender::unbounded_send(&self.requests_tx, (tx, message));
        rx.map_err(|()| NetlinkIpError::ConnectionClosed)
    }

    pub fn get_links(&mut self) -> impl Future<Item = Vec<Link>, Error = NetlinkIpError> {
        // build the request
        let mut req: Message = RtnlMessage::GetLink(LinkMessage {
            header: LinkHeader {
                address_family: 0, // AF_UNSPEC
                link_layer_type: LinkLayerType::Ether,
                flags: LinkFlags::new(),
                change_mask: LinkFlags::new(),
                index: 0,
            },
            nlas: vec![],
        }).into();
        req.set_flags(NetlinkFlags::from(
            constants::NLM_F_DUMP | constants::NLM_F_REQUEST,
        ));

        // send the request
        let rx = self.request(req);

        // handle the response: FutureVec turns the response messages into a vec of Link.
        let nl_handle = self.clone();
        FutureVec::new(rx.map(move |msg| {
            if !msg.is_new_link() {
                return Err(NetlinkIpError::UnexpectedMessage(msg));
            }

            if let (_, RtnlMessage::NewLink(link_message)) = msg.into_parts() {
                Ok(Link::new(
                    nl_handle.clone(),
                    LinkData::from_link_message(link_message)?,
                ))
            } else {
                // We checked that msg.is_new_link() above, so the should not be reachable.
                unreachable!();
            }
        }))
    }

    pub fn new_link(&self, link: LinkData) -> Link {
        Link::new(self.clone(), link)
    }
}

struct FutureVec<S, T>(S, Option<Vec<T>>);

impl<S, T> FutureVec<S, T> {
    fn new(s: S) -> Self {
        FutureVec(s, Some(vec![]))
    }
}

impl<S: Stream<Item = Result<T, NetlinkIpError>, Error = NetlinkIpError>, T> Future
    for FutureVec<S, T>
{
    type Item = Vec<T>;
    type Error = NetlinkIpError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.0.poll()? {
                Async::Ready(Some(item)) => self.1.as_mut().unwrap().push(item?),
                Async::Ready(None) => {
                    return Ok(Async::Ready(mem::replace(&mut self.1, None).unwrap()))
                }
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}
