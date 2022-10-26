// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};

use netlink_packet_xfrm::{policy::FlushMessage, UserPolicyType, XfrmAttrs, XfrmMessage};

use crate::{try_nl, Error, Handle};

/// A request to flush xfrm policies. This is equivalent to the `ip xfrm policy flush` command.
pub struct PolicyFlushRequest {
    handle: Handle,
    message: FlushMessage,
}

impl PolicyFlushRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let message = FlushMessage::default();

        PolicyFlushRequest { handle, message }
    }

    // Use XFRM_POLICY_TYPE_MAIN or XFRM_POLICY_TYPE_SUB.
    // The kernel doesn't like specifying an attribute of
    // XFRM_POLICY_TYPE_ANY (it returns -EINVAL).
    pub fn ptype(mut self, ptype: u8) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::PolicyType(UserPolicyType {
                ptype,
                ..Default::default()
            }));
        self
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let PolicyFlushRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::FlushPolicy(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    /// Execute the request without waiting for an ACK response.
    pub fn execute_noack(self) -> Result<(), Error> {
        let PolicyFlushRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::FlushPolicy(message));
        req.header.flags = NLM_F_REQUEST;

        let mut _response = handle.request(req)?;

        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut FlushMessage {
        &mut self.message
    }
}
