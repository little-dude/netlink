// SPDX-License-Identifier: MIT

use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
};

use futures::stream::StreamExt;

use crate::{
    flags::NewFlags,
    packet::{constants::*, nlas::rule::Nla, NetlinkMessage, RtnlMessage, RuleMessage},
    try_nl,
    Error,
    Handle,
};

/// A request to create a new rule. This is equivalent to the `ip rule add` command.
pub struct RuleAddRequest<T = ()> {
    handle: Handle,
    message: RuleMessage,
    flags: NewFlags,
    _phantom: PhantomData<T>,
}

impl<T> RuleAddRequest<T> {
    pub(crate) fn new(handle: Handle) -> Self {
        let mut message = RuleMessage::default();

        message.header.table = RT_TABLE_MAIN;
        message.header.action = FR_ACT_UNSPEC;

        RuleAddRequest {
            handle,
            message,
            flags: NewFlags::new() | NewFlags::EXCL,
            _phantom: Default::default(),
        }
    }

    /// Sets the input interface name.
    pub fn input_interface(mut self, ifname: String) -> Self {
        self.message.nlas.push(Nla::Iifname(ifname));
        self
    }

    /// Sets the output interface name.
    pub fn output_interface(mut self, ifname: String) -> Self {
        self.message.nlas.push(Nla::OifName(ifname));
        self
    }

    /// Sets the rule table.
    ///
    /// Default is main rule table.
    pub fn table(mut self, table: u8) -> Self {
        self.message.header.table = table;
        self
    }

    /// Set the tos.
    pub fn tos(mut self, tos: u8) -> Self {
        self.message.header.tos = tos;
        self
    }

    /// Set action.
    pub fn action(mut self, action: u8) -> Self {
        self.message.header.action = action;
        self
    }

    /// Build an IP v4 rule
    pub fn v4(mut self) -> RuleAddRequest<Ipv4Addr> {
        self.message.header.family = AF_INET as u8;
        RuleAddRequest {
            handle: self.handle,
            message: self.message,
            flags: self.flags,
            _phantom: Default::default(),
        }
    }

    /// Build an IP v6 rule
    pub fn v6(mut self) -> RuleAddRequest<Ipv6Addr> {
        self.message.header.family = AF_INET6 as u8;
        RuleAddRequest {
            handle: self.handle,
            message: self.message,
            flags: self.flags,
            _phantom: Default::default(),
        }
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let RuleAddRequest {
            mut handle,
            message,
            flags,
            ..
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::NewRule(message));
        req.header.flags = flags.bits();

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message);
        }

        Ok(())
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
    pub fn set_flags(mut self, flags: NewFlags) -> Self {
        self.flags = flags;
        self
    }
}

impl RuleAddRequest<Ipv4Addr> {
    /// Sets the source address prefix.
    pub fn source_prefix(mut self, addr: Ipv4Addr, prefix_length: u8) -> Self {
        self.message.header.src_len = prefix_length;
        let src = addr.octets().to_vec();
        self.message.nlas.push(Nla::Source(src));
        self
    }

    /// Sets the destination address prefix.
    pub fn destination_prefix(mut self, addr: Ipv4Addr, prefix_length: u8) -> Self {
        self.message.header.dst_len = prefix_length;
        let dst = addr.octets().to_vec();
        self.message.nlas.push(Nla::Destination(dst));
        self
    }
}

impl RuleAddRequest<Ipv6Addr> {
    /// Sets the source address prefix.
    pub fn source_prefix(mut self, addr: Ipv6Addr, prefix_length: u8) -> Self {
        self.message.header.src_len = prefix_length;
        let src = addr.octets().to_vec();
        self.message.nlas.push(Nla::Source(src));
        self
    }

    /// Sets the destination address prefix.
    pub fn destination_prefix(mut self, addr: Ipv6Addr, prefix_length: u8) -> Self {
        self.message.header.dst_len = prefix_length;
        let dst = addr.octets().to_vec();
        self.message.nlas.push(Nla::Destination(dst));
        self
    }
}
