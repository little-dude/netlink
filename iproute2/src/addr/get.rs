use futures::{Future, Stream};

use rtnetlink::constants::{NLM_F_DUMP, NLM_F_REQUEST};
use rtnetlink::{AddressMessage, NetlinkFlags, NetlinkMessage, RtnlMessage};

use super::Address;
use connection::ConnectionHandle;
use errors::NetlinkIpError;

use Stream2Vec;

lazy_static! {
    // Flags for `ip link get`
    static ref GET_FLAGS: NetlinkFlags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_DUMP);
}

pub struct AddressGetRequest {
    handle: ConnectionHandle,
    message: AddressMessage,
}

impl AddressGetRequest {
    pub(crate) fn new(handle: ConnectionHandle) -> Self {
        let message = AddressMessage::default();
        AddressGetRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = Vec<Address>, Error = NetlinkIpError> {
        Stream2Vec::new(
            self.get_address_msgs_stream()
                .map(|addr_msg| match addr_msg {
                    Ok(value) => Address::from_address_message(value),
                    Err(e) => Err(e),
                }),
        )
    }

    /// Get the raw rtnetlink address messages as a Stream
    pub(crate) fn get_address_msgs_stream(
        self,
    ) -> impl Stream<Item = Result<AddressMessage, NetlinkIpError>, Error = NetlinkIpError> {
        let AddressGetRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::GetAddress(message));
        req.header_mut().set_flags(*GET_FLAGS);
        handle.request(req).map(move |msg| {
            if !msg.is_new_address() {
                return Err(NetlinkIpError::UnexpectedMessage(msg));
            }

            if let (_, RtnlMessage::NewAddress(addr_message)) = msg.into_parts() {
                Ok(addr_message)
            } else {
                // We checked that msg.is_new_address() above, so the else should not be reachable.
                unreachable!();
            }
        })
    }

    /// Get the raw rtnetlink address messages as a Stream
    pub(crate) fn get_address_msgs_future(
        self,
    ) -> impl Future<Item = Vec<AddressMessage>, Error = NetlinkIpError> {
        Stream2Vec::new(self.get_address_msgs_stream())
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut AddressMessage {
        &mut self.message
    }
}
