// SPDX-License-Identifier: MIT

//use futures::stream::StreamExt;
use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};
use std::net::IpAddr;

use netlink_packet_core::{NetlinkMessage, NLM_F_DUMP, NLM_F_REQUEST};

use netlink_packet_xfrm::{
    constants::*,
    policy::{DelGetMessage, ModifyMessage},
    Address, Mark, SecurityCtx, UserPolicyType, XfrmAttrs, XfrmMessage,
};

use crate::{try_xfrmnl, Error, Handle};

/// A request to get xfrm policies. This is equivalent to the `ip xfrm policy get` command.
pub struct PolicyGetRequest {
    handle: Handle,
    message: DelGetMessage,
    dump: bool,
}

impl PolicyGetRequest {
    pub(crate) fn new(
        handle: Handle,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
        direction: u8,
    ) -> Self {
        let mut message = DelGetMessage::default();

        match src_addr {
            IpAddr::V4(ipv4) => {
                message.user_policy_id.selector.saddr = Address::from_ipv4(&ipv4);
                if ipv4.is_unspecified() {
                    message.user_policy_id.selector.prefixlen_s = 0;
                } else {
                    message.user_policy_id.selector.prefixlen_s = src_prefix_len;
                }
                message.user_policy_id.selector.family = AF_INET;
            }
            IpAddr::V6(ipv6) => {
                message.user_policy_id.selector.saddr = Address::from_ipv6(&ipv6);
                if ipv6.is_unspecified() {
                    message.user_policy_id.selector.prefixlen_s = 0;
                } else {
                    message.user_policy_id.selector.prefixlen_s = src_prefix_len;
                }
                message.user_policy_id.selector.family = AF_INET6;
            }
        }

        match dst_addr {
            IpAddr::V4(ipv4) => {
                message.user_policy_id.selector.daddr = Address::from_ipv4(&ipv4);
                if ipv4.is_unspecified() {
                    message.user_policy_id.selector.prefixlen_d = 0;
                } else {
                    message.user_policy_id.selector.prefixlen_d = dst_prefix_len;
                }
            }
            IpAddr::V6(ipv6) => {
                message.user_policy_id.selector.daddr = Address::from_ipv6(&ipv6);
                if ipv6.is_unspecified() {
                    message.user_policy_id.selector.prefixlen_d = 0;
                } else {
                    message.user_policy_id.selector.prefixlen_d = dst_prefix_len;
                }
            }
        }

        message.user_policy_id.direction = direction;

        PolicyGetRequest {
            handle,
            message,
            dump: false,
        }
    }

    pub(crate) fn new_index(handle: Handle, index: u32, direction: u8) -> Self {
        let mut message = DelGetMessage::default();

        message.user_policy_id.index = index;
        message.user_policy_id.direction = direction;

        PolicyGetRequest {
            handle,
            message,
            dump: false,
        }
    }

    pub(crate) fn new_dump(handle: Handle) -> Self {
        let message = DelGetMessage::default();

        PolicyGetRequest {
            handle,
            message,
            dump: true,
        }
    }

    pub fn direction(mut self, direction: u8) -> Self {
        self.message.user_policy_id.direction = direction;
        self
    }

    pub fn ptype(mut self, ptype: u8) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::PolicyType(UserPolicyType {
                ptype,
                ..Default::default()
            }));
        self
    }
    pub fn security_context(mut self, secctx: &Vec<u8>) -> Self {
        let mut sc = SecurityCtx::default();

        sc.context(secctx);
        self.message.nlas.push(XfrmAttrs::SecurityContext(sc));
        self
    }

    /// Manually change the policy index instead of letting the kernel choose one.
    /// Only certain values will work, and it depends on the direction.
    /// The kernel does a bitwise 'and' on the index with 7, and compares it with
    /// the direction ((index & 7) == dir). For example:
    ///   XFRM_POLICY_IN  (0) -- valid indexes are: 8, 16, 24, 32, 40...
    ///   XFRM_POLICY_OUT (1) -- valid indexes are: 1, 9, 17, 25, 33...
    ///   XFRM_POLICY_FWD (2) -- valid indexes are: 2, 10, 18, 26, 34...
    /// If this pattern is not followed, the kernel will return -EINVAL (Invalid argument).
    pub fn index(mut self, index: u32) -> Self {
        self.message.user_policy_id.index = index;
        self
    }
    pub fn ifid(mut self, ifid: u32) -> Self {
        self.message.nlas.push(XfrmAttrs::IfId(ifid));
        self
    }
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::Mark(Mark { value: mark, mask }));
        self
    }

    pub fn selector_protocol(mut self, proto: u8) -> Self {
        self.message.user_policy_id.selector.proto = proto;
        self
    }
    pub fn selector_protocol_src_port(mut self, port: u16) -> Self {
        self.message.user_policy_id.selector.sport = port;
        self.message.user_policy_id.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_dst_port(mut self, port: u16) -> Self {
        self.message.user_policy_id.selector.dport = port;
        self.message.user_policy_id.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_type(mut self, proto_type: u8) -> Self {
        self.message.user_policy_id.selector.sport = proto_type as u16;
        self.message.user_policy_id.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_code(mut self, proto_code: u8) -> Self {
        self.message.user_policy_id.selector.dport = proto_code as u16;
        self.message.user_policy_id.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_gre_key(mut self, gre_key: u32) -> Self {
        self.message.user_policy_id.selector.sport = (gre_key >> 16) as u16;
        self.message.user_policy_id.selector.sport_mask = u16::MAX;
        self.message.user_policy_id.selector.dport = (gre_key & 0xffff) as u16;
        self.message.user_policy_id.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_dev_id(mut self, id: u32) -> Self {
        self.message.user_policy_id.selector.ifindex = id as i32;
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = ModifyMessage, Error = Error> {
        let PolicyGetRequest {
            mut handle,
            message,
            dump,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::GetPolicy(message));

        if dump {
            req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        } else {
            req.header.flags = NLM_F_REQUEST;
        }

        // A successful policy Get request returns with an Add/ModifyMessage response.
        match handle.request(req) {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_xfrmnl!(msg, XfrmMessage::AddPolicy))))
            }
            Err(e) => Either::Right(future::err::<ModifyMessage, Error>(e).into_stream()),
        }
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut DelGetMessage {
        &mut self.message
    }
}
