// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{AcquireMessageBuffer, UserAcquire, UserAcquireBuffer, XfrmAttrs};

use netlink_packet_utils::{traits::*, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AcquireMessage {
    pub acquire: UserAcquire,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for AcquireMessage {
    fn buffer_len(&self) -> usize {
        self.acquire.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.acquire.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.acquire.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<AcquireMessageBuffer<&'a T>> for AcquireMessage {
    fn parse(buf: &AcquireMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let acquire = UserAcquire::parse(&UserAcquireBuffer::new(&buf.acquire()))
            .context("failed to parse monitor acquire message info")?;
        Ok(AcquireMessage {
            acquire,
            nlas: Vec::<XfrmAttrs>::parse(buf)
                .context("failed to parse monitor acquire message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<AcquireMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &AcquireMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
