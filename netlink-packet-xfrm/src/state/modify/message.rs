// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    state::ModifyMessageBuffer,
    UserSaInfo,
    UserSaInfoBuffer,
    XfrmAttrs,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ModifyMessage {
    pub user_sa_info: UserSaInfo,
    pub nlas: Vec<XfrmAttrs>
}

impl Emitable for ModifyMessage {
    fn buffer_len(&self) -> usize {
        self.user_sa_info.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.user_sa_info.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.user_sa_info.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<ModifyMessageBuffer<&'a T>> for ModifyMessage {
    fn parse(buf: &ModifyMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let user_sa_info = UserSaInfo::parse(&UserSaInfoBuffer::new(&buf.user_sa_info()))
            .context("failed to parse state modify message user sa info")?;
        Ok(ModifyMessage {
            user_sa_info,
            nlas: Vec::<XfrmAttrs>::parse(buf).context("failed to parse state modify message NLAs")?
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<ModifyMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &ModifyMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
