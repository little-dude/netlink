// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};

use netlink_packet_xfrm::{policy::DefaultMessage, XfrmMessage};

use crate::{try_nl, try_xfrmnl, Error, Handle};

/// A request to get the default xfrm action for input, output, forward policies. This is equivalent to the `ip xfrm policy getdefault` command.
pub struct PolicyGetDefaultRequest {
    handle: Handle,
    message: DefaultMessage,
}

impl PolicyGetDefaultRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let message = DefaultMessage::default();

        PolicyGetDefaultRequest { handle, message }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<DefaultMessage, Error> {
        let PolicyGetDefaultRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::GetPolicyDefault(message));

        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(msg) = response.next().await {
            return Ok(try_xfrmnl!(msg, XfrmMessage::GetPolicyDefault));
        }
        Err(Error::RequestFailed)
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut DefaultMessage {
        &mut self.message
    }
}

/// A request to set the default xfrm action for input, output, forward policies. This is equivalent to the `ip xfrm policy setdefault` command.
pub struct PolicySetDefaultRequest {
    handle: Handle,
    message: DefaultMessage,
}

impl PolicySetDefaultRequest {
    pub(crate) fn new(handle: Handle, in_act: u8, fwd_act: u8, out_act: u8) -> Self {
        let mut message = DefaultMessage::default();

        message.user_policy.input = in_act;
        message.user_policy.forward = fwd_act;
        message.user_policy.output = out_act;

        PolicySetDefaultRequest { handle, message }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let PolicySetDefaultRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::SetPolicyDefault(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(msg) = response.next().await {
            try_nl!(msg);
        }
        Ok(())
    }

    /// Execute the request without waiting for an ACK response.
    pub fn execute_noack(self) -> Result<(), Error> {
        let PolicySetDefaultRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::SetPolicyDefault(message));
        req.header.flags = NLM_F_REQUEST;

        let mut _response = handle.request(req)?;

        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut DefaultMessage {
        &mut self.message
    }
}
