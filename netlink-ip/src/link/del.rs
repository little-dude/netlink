use futures::Future;

use netlink_sys::constants::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use netlink_sys::rtnl::{LinkMessage, Message, RtnlMessage};
use netlink_sys::NetlinkFlags;

use connection::ConnectionHandle;
use errors::NetlinkIpError;

use Stream2Ack;

lazy_static! {
    // Flags for `ip link del`
    static ref DEL_FLAGS: NetlinkFlags =
        NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct DelRequest {
    handle: ConnectionHandle,
    message: LinkMessage,
}

impl DelRequest {
    pub(crate) fn new(handle: ConnectionHandle, index: u32) -> Self {
        let mut message = LinkMessage::new();
        message.header_mut().set_index(index);
        DelRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = NetlinkIpError> {
        let DelRequest {
            mut handle,
            message,
        } = self;
        let mut req = Message::from(RtnlMessage::DelLink(message));
        req.header_mut().set_flags(*DEL_FLAGS);
        Stream2Ack::new(handle.request(req))
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }
}
