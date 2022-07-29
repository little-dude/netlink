// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    PolicyExpireMessageBuffer,
    UserPolicyExpire,
    UserPolicyExpireBuffer,
    XfrmAttrs,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct PolicyExpireMessage {
    pub expire: UserPolicyExpire,
    pub nlas: Vec<XfrmAttrs>
}

impl Emitable for PolicyExpireMessage {
    fn buffer_len(&self) -> usize {
        self.expire.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.expire.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.expire.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<PolicyExpireMessageBuffer<&'a T>> for PolicyExpireMessage {
    fn parse(buf: &PolicyExpireMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let expire = UserPolicyExpire::parse(&UserPolicyExpireBuffer::new(&buf.expire()))
            .context("failed to parse monitor policy expire message info")?;
        Ok(PolicyExpireMessage {
            expire,
            nlas: Vec::<XfrmAttrs>::parse(buf).context("failed to parse monitor policy expire message NLAs")?
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<PolicyExpireMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &PolicyExpireMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
