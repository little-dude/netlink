// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    state::DelGetMessageBuffer,
    UserSaId,
    UserSaIdBuffer,
    XfrmAttrs,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DelGetMessage {
    pub user_sa_id: UserSaId,
    pub nlas: Vec<XfrmAttrs>
}

impl Emitable for DelGetMessage {
    fn buffer_len(&self) -> usize {
        self.user_sa_id.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.user_sa_id.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.user_sa_id.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<DelGetMessageBuffer<&'a T>> for DelGetMessage {
    fn parse(buf: &DelGetMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let user_sa_id = UserSaId::parse(&UserSaIdBuffer::new(&buf.user_sa_id()))
            .context("failed to parse state delget message user sa id")?;
        Ok(DelGetMessage {
            user_sa_id,
            nlas: Vec::<XfrmAttrs>::parse(buf).context("failed to parse state delget message NLAs")?
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<DelGetMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &DelGetMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
