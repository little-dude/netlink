// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;
use std::net::IpAddr;

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};

use netlink_packet_xfrm::{
    constants::*, state::DelGetMessage, Address, Mark, XfrmAttrs, XfrmMessage,
};

use crate::{try_nl, Error, Handle};

/// A request to delete xfrm state. This is equivalent to the `ip xfrm state delete` command.
pub struct StateDeleteRequest {
    handle: Handle,
    message: DelGetMessage,
}

impl StateDeleteRequest {
    pub(crate) fn new(
        handle: Handle,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: u8,
        spi: u32,
    ) -> Self {
        let mut message = DelGetMessage::default();

        match src_addr {
            IpAddr::V4(ipv4) => {
                message
                    .nlas
                    .push(XfrmAttrs::SrcAddr(Address::from_ipv4(&ipv4)));
                message.user_sa_id.family = AF_INET;
            }
            IpAddr::V6(ipv6) => {
                message
                    .nlas
                    .push(XfrmAttrs::SrcAddr(Address::from_ipv6(&ipv6)));
                message.user_sa_id.family = AF_INET6;
            }
        }

        match dst_addr {
            IpAddr::V4(ipv4) => {
                message.user_sa_id.daddr = Address::from_ipv4(&ipv4);
            }
            IpAddr::V6(ipv6) => {
                message.user_sa_id.daddr = Address::from_ipv6(&ipv6);
            }
        }

        message.user_sa_id.proto = protocol;
        message.user_sa_id.spi = spi;

        StateDeleteRequest { handle, message }
    }

    // Delete and Get won't work to find/retrieve the state in the kernel
    // if mask is set incorrectly during the state Add. i.e. if the mask
    // is set in such a way that it doesn't cover the mark, a full flush
    // may be needed to delete it.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::Mark(Mark { value: mark, mask }));
        self
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let StateDeleteRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::DeleteSa(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    /// Execute the request without waiting for an ACK response.
    pub fn execute_noack(self) -> Result<(), Error> {
        let StateDeleteRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::DeleteSa(message));
        req.header.flags = NLM_F_REQUEST;

        let mut _response = handle.request(req)?;

        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut DelGetMessage {
        &mut self.message
    }
}
