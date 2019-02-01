use futures::{Future, Stream};

use crate::packet::constants::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use crate::packet::{NetlinkFlags, NetlinkMessage, NetlinkPayload, RtnlMessage};

use super::AddressHandle;
use crate::{Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip addr del`
    static ref DEL_FLAGS: NetlinkFlags =
        NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct AddressFlushRequest {
    handle: Handle,
    index: u32,
}

impl AddressFlushRequest {
    pub(crate) fn new(handle: Handle, index: u32) -> Self {
        AddressFlushRequest { handle, index }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let handle = self.handle.clone();
        let index = self.index;
        AddressHandle::new(self.handle.clone())
            .get()
            .execute()
            .filter(move |msg| msg.header.index == index)
            .map(move |msg| {
                let mut req = NetlinkMessage::from(RtnlMessage::DelAddress(msg));
                req.header.flags = *DEL_FLAGS;
                handle.clone().request(req).for_each(|message| {
                    if let NetlinkPayload::Error(err) = message.payload {
                        Err(ErrorKind::NetlinkError(err).into())
                    } else {
                        Ok(())
                    }
                })
            })
            // 0xff is arbitrary. It is the max amount of futures that will be
            // buffered.
            .buffer_unordered(0xff)
            // turn the stream into a future.
            .for_each(|()| Ok(()))
    }
}
