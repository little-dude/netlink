use futures::Stream;

use crate::netlink_packet_route::{link::LinkMessage, RtnlMessage};
use netlink_packet_core::{
    header::flags::{NLM_F_DUMP, NLM_F_REQUEST},
    NetlinkFlags, NetlinkMessage, NetlinkPayload,
};

use crate::{Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip link get`
    static ref GET_FLAGS: NetlinkFlags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_DUMP);
}

pub struct LinkGetRequest {
    handle: Handle,
    message: LinkMessage,
}

impl LinkGetRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let message = LinkMessage::new();
        LinkGetRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Stream<Item = LinkMessage, Error = Error> {
        let LinkGetRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::GetLink(message));
        req.header.flags = *GET_FLAGS;
        handle.request(req).and_then(move |msg| {
            let (header, payload) = msg.into_parts();
            match payload {
                NetlinkPayload::InnerMessage(RtnlMessage::NewLink(msg)) => Ok(msg),
                NetlinkPayload::Error(err) => Err(ErrorKind::NetlinkError(err).into()),
                _ => Err(ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into()),
            }
        })
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }
}
