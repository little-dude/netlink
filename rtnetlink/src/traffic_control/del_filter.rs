// SPDX-License-Identifier: MIT
use futures::StreamExt;

use crate::{
    packet::{NetlinkMessage, RtnlMessage, TcMessage, NLM_F_ACK, NLM_F_REQUEST},
    try_nl,
    Error,
    Handle,
};

pub struct TrafficFilterDelRequest {
    handle: Handle,
    message: TcMessage,
}

impl TrafficFilterDelRequest {
    pub(crate) fn new(handle: Handle, message: TcMessage) -> Self {
        TrafficFilterDelRequest { handle, message }
    }

    pub fn parent(mut self, parent: u32) -> Self {
        self.message.header.parent = parent;
        self
    }

    // Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let TrafficFilterDelRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::DelTrafficFilter(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message)
        }
        Ok(())
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut TcMessage {
        &mut self.message
    }
}
