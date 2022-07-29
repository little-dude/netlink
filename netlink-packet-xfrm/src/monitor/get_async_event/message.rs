// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    AsyncEventId,
    AsyncEventIdBuffer,
    GetAsyncEventMessageBuffer,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct GetAsyncEventMessage {
    pub id: AsyncEventId
}

impl Emitable for GetAsyncEventMessage {
    fn buffer_len(&self) -> usize {
        self.id.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.id.emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<GetAsyncEventMessageBuffer<&'a T>> for GetAsyncEventMessage {
    fn parse(buf: &GetAsyncEventMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let id = AsyncEventId::parse(&AsyncEventIdBuffer::new(&buf.id()))
            .context("failed to parse monitor get async event id")?;
        Ok(GetAsyncEventMessage {
            id
        })
    }
}
