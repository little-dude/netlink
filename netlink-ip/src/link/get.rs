use futures::{Future, Stream};

use netlink_sys::constants::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_sys::rtnl::{LinkMessage, Message, RtnlMessage};
use netlink_sys::NetlinkFlags;

use super::Link;
use connection::ConnectionHandle;
use errors::NetlinkIpError;

use Stream2Vec;

lazy_static! {
    // Flags for `ip link get`
    static ref GET_FLAGS: NetlinkFlags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_DUMP);
}

pub struct GetRequest {
    handle: ConnectionHandle,
    message: LinkMessage,
}

impl GetRequest {
    pub(crate) fn new(handle: ConnectionHandle) -> Self {
        let message = LinkMessage::new();
        GetRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = Vec<Link>, Error = NetlinkIpError> {
        let GetRequest {
            mut handle,
            message,
        } = self;
        let mut req = Message::from(RtnlMessage::GetLink(message));
        req.header_mut().set_flags(*GET_FLAGS);
        Stream2Vec::new(handle.request(req).map(move |msg| {
            if !msg.is_new_link() {
                return Err(NetlinkIpError::UnexpectedMessage(msg));
            }

            if let (_, RtnlMessage::NewLink(link_message)) = msg.into_parts() {
                Ok(Link::from_link_message(link_message)?)
            } else {
                // We checked that msg.is_new_link() above, so the should not be reachable.
                unreachable!();
            }
        }))
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }
}
