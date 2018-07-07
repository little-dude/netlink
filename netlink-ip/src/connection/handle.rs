use futures::sync::mpsc::{unbounded, UnboundedSender};
use futures::Stream;
use netlink_sys::rtnl::Message;
use LinkHandle;

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
        debug!("handle: forwarding new request to connection");
        let _ = UnboundedSender::unbounded_send(&self.requests_tx, (tx, message));
        rx.map_err(|()| {
            error!("could not forward new request to connection: the connection is closed");
            NetlinkIpError::ConnectionClosed
        })
    }

    pub fn link(&self) -> LinkHandle {
        LinkHandle::new(self.clone())
    }
}
