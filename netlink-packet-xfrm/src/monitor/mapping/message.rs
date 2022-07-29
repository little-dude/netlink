// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    MappingMessageBuffer,
    UserMapping,
    UserMappingBuffer,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct MappingMessage {
    pub map: UserMapping
}

impl Emitable for MappingMessage {
    fn buffer_len(&self) -> usize {
        self.map.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.map.emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MappingMessageBuffer<&'a T>> for MappingMessage {
    fn parse(buf: &MappingMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let map = UserMapping::parse(&UserMappingBuffer::new(&buf.map()))
            .context("failed to parse monitor mapping message info")?;
        Ok(MappingMessage {
            map
        })
    }
}
