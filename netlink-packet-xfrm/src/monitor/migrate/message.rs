// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{MigrateMessageBuffer, UserPolicyId, UserPolicyIdBuffer, XfrmAttrs};

use netlink_packet_utils::{traits::*, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct MigrateMessage {
    pub user_policy_id: UserPolicyId,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for MigrateMessage {
    fn buffer_len(&self) -> usize {
        self.user_policy_id.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.user_policy_id.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.user_policy_id.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MigrateMessageBuffer<&'a T>> for MigrateMessage {
    fn parse(buf: &MigrateMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let user_policy_id = UserPolicyId::parse(&UserPolicyIdBuffer::new(&buf.user_policy_id()))
            .context("failed to parse migrate message user policy id")?;
        Ok(MigrateMessage {
            user_policy_id,
            nlas: Vec::<XfrmAttrs>::parse(buf)
                .context("failed to parse monitor migrate message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MigrateMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &MigrateMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
