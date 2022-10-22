// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{ExpireMessageBuffer, UserExpire, UserExpireBuffer};

use netlink_packet_utils::{traits::*, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ExpireMessage {
    pub expire: UserExpire,
}

impl Emitable for ExpireMessage {
    fn buffer_len(&self) -> usize {
        self.expire.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.expire.emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<ExpireMessageBuffer<&'a T>> for ExpireMessage {
    fn parse(buf: &ExpireMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let expire = UserExpire::parse(&UserExpireBuffer::new(&buf.expire()))
            .context("failed to parse monitor expire message info")?;
        Ok(ExpireMessage { expire })
    }
}
