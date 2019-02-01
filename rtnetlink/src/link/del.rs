use futures::{Future, Stream};

use crate::packet::constants::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use crate::packet::{LinkMessage, NetlinkFlags, NetlinkMessage, NetlinkPayload, RtnlMessage};
use crate::{Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip link del`
    static ref DEL_FLAGS: NetlinkFlags =
        NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct LinkDelRequest {
    handle: Handle,
    message: LinkMessage,
}

impl LinkDelRequest {
    pub(crate) fn new(handle: Handle, index: u32) -> Self {
        let mut message = LinkMessage::new();
        message.header.index = index;
        LinkDelRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let LinkDelRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::DelLink(message));
        req.header.flags = *DEL_FLAGS;
        handle.request(req).for_each(|message| {
            if let NetlinkPayload::Error(err) = message.payload {
                Err(ErrorKind::NetlinkError(err).into())
            } else {
                Ok(())
            }
        })
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }
}
