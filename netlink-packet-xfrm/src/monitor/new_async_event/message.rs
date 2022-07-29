// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    AsyncEventId,
    AsyncEventIdBuffer,
    NewAsyncEventMessageBuffer,
    XfrmAttrs,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewAsyncEventMessage {
    pub id: AsyncEventId,
    pub nlas: Vec<XfrmAttrs>
}

impl Emitable for NewAsyncEventMessage {
    fn buffer_len(&self) -> usize {
        self.id.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.id.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.id.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NewAsyncEventMessageBuffer<&'a T>> for NewAsyncEventMessage {
    fn parse(buf: &NewAsyncEventMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let id = AsyncEventId::parse(&AsyncEventIdBuffer::new(&buf.id()))
            .context("failed to parse monitor new async event id")?;
        Ok(NewAsyncEventMessage {
            id,
            nlas: Vec::<XfrmAttrs>::parse(buf).context("failed to parse monitor new async event message NLAs")?
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NewAsyncEventMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &NewAsyncEventMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
