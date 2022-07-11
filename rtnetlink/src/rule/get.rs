// SPDX-License-Identifier: MIT

use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};

use crate::{
    flags::GetFlags,
    packet::{constants::*, NetlinkMessage, RtnlMessage, RuleMessage},
    try_rtnl,
    Error,
    Handle,
    IpVersion,
};

pub struct RuleGetRequest {
    handle: Handle,
    message: RuleMessage,
    flags: GetFlags,
}

impl RuleGetRequest {
    pub(crate) fn new(handle: Handle, ip_version: IpVersion) -> Self {
        let mut message = RuleMessage::default();
        message.header.family = ip_version.family();

        message.header.dst_len = 0;
        message.header.src_len = 0;
        message.header.tos = 0;
        message.header.action = FR_ACT_UNSPEC;
        message.header.table = RT_TABLE_UNSPEC;

        RuleGetRequest {
            handle,
            message,
            flags: GetFlags::new() | GetFlags::DUMP,
        }
    }

    pub fn message_mut(&mut self) -> &mut RuleMessage {
        &mut self.message
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

    pub fn execute(self) -> impl TryStream<Ok = RuleMessage, Error = Error> {
        let RuleGetRequest {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::GetRule(message));
        req.header.flags = flags.bits();

        match handle.request(req) {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_rtnl!(msg, RtnlMessage::NewRule))))
            }
            Err(e) => Either::Right(future::err::<RuleMessage, Error>(e).into_stream()),
        }
    }
}
