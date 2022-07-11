// SPDX-License-Identifier: MIT

use crate::{
    flags::NewFlags,
    packet::{
        nlas::link::{Nla, Prop},
        LinkMessage,
        NetlinkMessage,
        NetlinkPayload,
        RtnlMessage,
    },
    Error,
    Handle,
};
use futures::stream::StreamExt;

pub struct LinkNewPropRequest {
    handle: Handle,
    message: LinkMessage,
    flags: NewFlags,
}

impl LinkNewPropRequest {
    pub(crate) fn new(handle: Handle, index: u32) -> Self {
        let mut message = LinkMessage::default();
        message.header.index = index;
        let flags = NewFlags::new() | NewFlags::EXCL | NewFlags::APPEND;
        LinkNewPropRequest {
            handle,
            message,
            flags,
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let LinkNewPropRequest {
            mut handle,
            message,
            flags,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::NewLinkProp(message));
        req.header.flags = flags.bits();

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            if let NetlinkPayload::Error(err) = message.payload {
                return Err(Error::NetlinkError(err));
            }
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
    pub fn set_flags(mut self, flags: NewFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Add alternative name to the link. This is equivalent to `ip link property add altname
    /// ALT_IFNAME dev LINK`.
    pub fn alt_ifname(mut self, alt_ifnames: &[&str]) -> Self {
        let mut props = Vec::new();
        for alt_ifname in alt_ifnames {
            props.push(Prop::AltIfName(alt_ifname.to_string()));
        }

        self.message.nlas.push(Nla::PropList(props));
        self
    }
}
