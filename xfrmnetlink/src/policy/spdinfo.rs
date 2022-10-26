// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};

use netlink_packet_xfrm::{
    policy::{GetSpdInfoMessage, NewSpdInfoMessage},
    SpdHThresh, SpdInfoAttrs, XfrmMessage,
};

use crate::{try_nl, try_xfrmnl, Error, Handle};

/// A request to get xfrm policy statistics. This is equivalent to the `ip xfrm policy count` command.
pub struct PolicyGetSpdInfoRequest {
    handle: Handle,
    message: GetSpdInfoMessage,
}

impl PolicyGetSpdInfoRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let mut message = GetSpdInfoMessage::default();
        message.flags = u32::MAX;

        PolicyGetSpdInfoRequest { handle, message }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<NewSpdInfoMessage, Error> {
        let PolicyGetSpdInfoRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::GetSpdInfo(message));

        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(msg) = response.next().await {
            return Ok(try_xfrmnl!(msg, XfrmMessage::NewSpdInfo));
        }
        Err(Error::RequestFailed)
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut GetSpdInfoMessage {
        &mut self.message
    }
}

/// A request to set xfrm policy statistics. This is equivalent to the `ip xfrm policy set` command.
pub struct PolicySetSpdInfoRequest {
    handle: Handle,
    message: NewSpdInfoMessage,
}

impl PolicySetSpdInfoRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let mut message = NewSpdInfoMessage::default();
        message.flags = u32::MAX;

        PolicySetSpdInfoRequest { handle, message }
    }

    pub fn hthresh4(mut self, lbits: u8, rbits: u8) -> Self {
        if lbits <= 32 && rbits <= 32 {
            self.message
                .nlas
                .push(SpdInfoAttrs::SpdIpv4HThresh(SpdHThresh { lbits, rbits }));
        }
        self
    }

    pub fn hthresh6(mut self, lbits: u8, rbits: u8) -> Self {
        if lbits <= 128 && rbits <= 128 {
            self.message
                .nlas
                .push(SpdInfoAttrs::SpdIpv6HThresh(SpdHThresh { lbits, rbits }));
        }
        self
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let PolicySetSpdInfoRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::NewSpdInfo(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(msg) = response.next().await {
            try_nl!(msg);
        }
        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut NewSpdInfoMessage {
        &mut self.message
    }
}
