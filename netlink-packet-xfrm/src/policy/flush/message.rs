// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    policy::FlushMessageBuffer,
    XfrmAttrs,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct FlushMessage {
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for FlushMessage {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas
            .as_slice()
            .emit(&mut buffer[0..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<FlushMessageBuffer<&'a T>> for FlushMessage {
    fn parse(buf: &FlushMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(FlushMessage {
            nlas: Vec::<XfrmAttrs>::parse(buf).context("failed to parse policy flush message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<FlushMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &FlushMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
