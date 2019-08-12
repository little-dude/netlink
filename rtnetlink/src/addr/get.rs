use futures::Stream;

use netlink_packet_core::{
    header::flags::{NLM_F_DUMP, NLM_F_REQUEST},
    NetlinkFlags, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{address::AddressMessage, RtnlMessage};

use crate::{Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip link get`
    static ref GET_FLAGS: NetlinkFlags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_DUMP);
}

pub struct AddressGetRequest {
    handle: Handle,
    message: AddressMessage,
}

impl AddressGetRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let message = AddressMessage::default();
        AddressGetRequest { handle, message }
    }

    pub fn execute(self) -> impl Stream<Item = AddressMessage, Error = Error> {
        let AddressGetRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::GetAddress(message));
        req.header.flags = *GET_FLAGS;
        handle.request(req).and_then(move |msg| {
            let (header, payload) = msg.into_parts();
            match payload {
                NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(msg)) => Ok(msg),
                NetlinkPayload::Error(err) => Err(ErrorKind::NetlinkError(err).into()),
                _ => Err(ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into()),
            }
        })
    }
}
