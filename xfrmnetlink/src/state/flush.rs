// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};

use netlink_packet_xfrm::{state::FlushMessage, XfrmMessage};

use crate::{try_nl, Error, Handle};

/// A request to flush xfrm policies. This is equivalent to the `ip xfrm policy flush` command.
pub struct StateFlushRequest {
    handle: Handle,
    message: FlushMessage,
}

impl StateFlushRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let message = FlushMessage::default();

        StateFlushRequest { handle, message }
    }

    pub fn protocol(mut self, protocol: u8) -> Self {
        self.message.protocol = protocol;
        self
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let StateFlushRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::FlushSa(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    /// Execute the request without waiting for an ACK response.
    pub fn execute_noack(self) -> Result<(), Error> {
        let StateFlushRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::FlushSa(message));
        req.header.flags = NLM_F_REQUEST;

        let mut _response = handle.request(req)?;

        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut FlushMessage {
        &mut self.message
    }
}
