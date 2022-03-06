// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use crate::{
    flags::DelFlags,
    packet::{LinkMessage, NetlinkMessage, RtnlMessage},
    try_nl,
    Error,
    Handle,
};

pub struct LinkDelRequest {
    handle: Handle,
    message: LinkMessage,
    flags: DelFlags,
}

impl LinkDelRequest {
    pub(crate) fn new(handle: Handle, index: u32) -> Self {
        let mut message = LinkMessage::default();
        message.header.index = index;
        LinkDelRequest {
            handle,
            message,
            flags: DelFlags::new(),
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let LinkDelRequest {
            mut handle,
            message,
            flags,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::DelLink(message));
        req.header.flags = flags.bits();

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message)
        }
        Ok(())
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
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
