// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use crate::{
    flags::DelFlags,
    packet::{NetlinkMessage, NetlinkPayload, RouteMessage, RtnlMessage},
    Error,
    Handle,
};

pub struct RouteDelRequest {
    handle: Handle,
    message: RouteMessage,
    flags: DelFlags,
}

impl RouteDelRequest {
    pub(crate) fn new(handle: Handle, message: RouteMessage) -> Self {
        RouteDelRequest {
            handle,
            message,
            flags: DelFlags::new(),
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let RouteDelRequest {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::DelRoute(message));
        req.header.flags = flags.bits();
        let mut response = handle.request(req)?;
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                return Err(Error::NetlinkError(e));
            }
        }
        Ok(())
    }

    pub fn message_mut(&mut self) -> &mut RouteMessage {
        &mut self.message
    }

    /// Set the netlink header flags.
    ///
    /// # Warning
    ///
    /// Altering the request's flags may render the request
    /// ineffective. Only set the flags if you know what you're doing.
    pub fn set_flags(mut self, flags: DelFlags) -> Self {
        self.flags = flags;
        self
    }
}
