// SPDX-License-Identifier: MIT

use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};

use crate::{
    flags::GetFlags,
    packet::{nlas::link::Nla, LinkMessage, NetlinkMessage, RtnlMessage},
    try_rtnl,
    Error,
    Handle,
};

pub struct LinkGetRequest {
    handle: Handle,
    message: LinkMessage,
    flags: GetFlags,
}

impl LinkGetRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        LinkGetRequest {
            handle,
            message: LinkMessage::default(),
            flags: GetFlags::new() | GetFlags::DUMP,
        }
    }

    /// Setting filter mask(e.g. RTEXT_FILTER_BRVLAN and etc)
    pub fn set_filter_mask(mut self, family: u8, filter_mask: u32) -> Self {
        self.message.header.interface_family = family;
        self.message.nlas.push(Nla::ExtMask(filter_mask));
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = LinkMessage, Error = Error> {
        let LinkGetRequest {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::GetLink(message));
        req.header.flags = flags.bits();

        match handle.request(req) {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_rtnl!(msg, RtnlMessage::NewLink))))
            }
            Err(e) => Either::Right(future::err::<LinkMessage, Error>(e).into_stream()),
        }
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }

    /// Lookup a link by index
    pub fn match_index(mut self, index: u32) -> Self {
        self.flags.remove(GetFlags::DUMP);
        self.message.header.index = index;
        self
    }

    /// Lookup a link by name
    ///
    /// This function requires support from your kernel (>= 2.6.33). If yours is
    /// older, consider filtering the resulting stream of links.
    pub fn match_name(mut self, name: String) -> Self {
        self.flags.remove(GetFlags::DUMP);
        self.message.nlas.push(Nla::IfName(name));
        self
    }

    /// Set the netlink header flags.
    ///
    /// # Warning
    ///
    /// Altering the request's flags may render the request
    /// ineffective. Only set the flags if you know what you're doing.
    pub fn set_flags(mut self, flags: GetFlags) -> Self {
        self.flags = flags;
        self
    }
}
