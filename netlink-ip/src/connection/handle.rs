use std::io;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use netlink_sys::rtnl::Message;

type RequestsTx = UnboundedSender<(UnboundedSender<Message>, Message)>;

pub struct ConnectionHandle {
    requests_tx: UnboundedSender<(UnboundedSender<Message>, Message)>,
}

impl ConnectionHandle {
    pub(crate) fn new(requests_tx: RequestsTx) -> Self {
        ConnectionHandle { requests_tx }
    }

    pub fn request<S>(&mut self, message: Message) -> io::Result<UnboundedReceiver<Message>> {
        let (tx, rx) = unbounded::<Message>();
        UnboundedSender::unbounded_send(&self.requests_tx, (tx, message)).unwrap();
        Ok(rx)
    }
}
