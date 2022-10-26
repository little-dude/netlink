// SPDX-License-Identifier: MIT

use crate::{state::FlushMessageBuffer, STATE_FLUSH_HEADER_LEN};

use netlink_packet_utils::{traits::*, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct FlushMessage {
    pub protocol: u8,
}

impl Emitable for FlushMessage {
    fn buffer_len(&self) -> usize {
        STATE_FLUSH_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = FlushMessageBuffer::new(buffer);
        buffer.set_protocol(self.protocol);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<FlushMessageBuffer<&'a T>> for FlushMessage {
    fn parse(buf: &FlushMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(FlushMessage {
            protocol: buf.protocol(),
        })
    }
}
