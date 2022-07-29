// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    DefaultMessageBuffer,
    POLICY_DEFAULT_HEADER_LEN,
    UserPolicyDefault,
    UserPolicyDefaultBuffer,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DefaultMessage {
    pub user_policy: UserPolicyDefault
}

impl Emitable for DefaultMessage {
    fn buffer_len(&self) -> usize {
        POLICY_DEFAULT_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.user_policy.emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<DefaultMessageBuffer<&'a T>> for DefaultMessage {
    fn parse(buf: &DefaultMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let user_policy = UserPolicyDefault::parse(&UserPolicyDefaultBuffer::new(&buf.user_policy()))
            .context("failed to parse policy default message user policy")?;
        Ok(DefaultMessage {
            user_policy
        })
    }
}
