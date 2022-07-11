// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use crate::{
    flags::DelFlags,
    packet::{AddressMessage, NetlinkMessage, RtnlMessage},
    try_nl,
    Error,
    Handle,
};

pub struct AddressDelRequest {
    handle: Handle,
    message: AddressMessage,
    flags: DelFlags,
}

impl AddressDelRequest {
    pub(crate) fn new(handle: Handle, message: AddressMessage) -> Self {
        AddressDelRequest {
            handle,
            message,
            flags: DelFlags::new(),
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let AddressDelRequest {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::DelAddress(message));
        req.header.flags = flags.bits();
        let mut response = handle.request(req)?;
        while let Some(msg) = response.next().await {
            try_nl!(msg);
        }
        Ok(())
    }

    pub fn message_mut(&mut self) -> &mut AddressMessage {
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
