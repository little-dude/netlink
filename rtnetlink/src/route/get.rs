// SPDX-License-Identifier: MIT

use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};

use crate::{
    flags::GetFlags,
    packet::{constants::*, NetlinkMessage, RouteMessage, RtnlMessage},
    try_rtnl,
    Error,
    Handle,
};

pub struct RouteGetRequest {
    handle: Handle,
    message: RouteMessage,
    flags: GetFlags,
}

/// Internet Protocol (IP) version.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd)]
pub enum IpVersion {
    /// IPv4
    V4,
    /// IPv6
    V6,
}

impl IpVersion {
    pub(crate) fn family(self) -> u8 {
        match self {
            IpVersion::V4 => AF_INET as u8,
            IpVersion::V6 => AF_INET6 as u8,
        }
    }
}

impl RouteGetRequest {
    pub(crate) fn new(handle: Handle, ip_version: IpVersion) -> Self {
        let mut message = RouteMessage::default();
        message.header.address_family = ip_version.family();

        // As per rtnetlink(7) documentation, setting the following
        // fields to 0 gets us all the routes from all the tables
        //
        // > For RTM_GETROUTE, setting rtm_dst_len and rtm_src_len to 0
        // > means you get all entries for the specified routing table.
        // > For the other fields, except rtm_table and rtm_protocol, 0
        // > is the wildcard.
        message.header.destination_prefix_length = 0;
        message.header.source_prefix_length = 0;
        message.header.scope = RT_SCOPE_UNIVERSE;
        message.header.kind = RTN_UNSPEC;

        // I don't know if these two fields matter
        message.header.table = RT_TABLE_UNSPEC;
        message.header.protocol = RTPROT_UNSPEC;

        RouteGetRequest {
            handle,
            message,
            flags: GetFlags::new() | GetFlags::DUMP,
        }
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
    pub fn set_flags(mut self, flags: GetFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn execute(self) -> impl TryStream<Ok = RouteMessage, Error = Error> {
        let RouteGetRequest {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::GetRoute(message));
        req.header.flags = flags.bits();

        match handle.request(req) {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_rtnl!(msg, RtnlMessage::NewRoute))))
            }
            Err(e) => Either::Right(future::err::<RouteMessage, Error>(e).into_stream()),
        }
    }
}
