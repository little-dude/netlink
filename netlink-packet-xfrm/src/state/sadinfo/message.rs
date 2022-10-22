// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    GetSadInfoMessageBuffer, NewSadInfoMessageBuffer, SadInfoAttrs, STATE_GET_SAD_INFO_HEADER_LEN,
    STATE_NEW_SAD_INFO_HEADER_LEN,
};

use netlink_packet_utils::{traits::*, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewSadInfoMessage {
    pub flags: u32,
    pub nlas: Vec<SadInfoAttrs>,
}

impl Emitable for NewSadInfoMessage {
    fn buffer_len(&self) -> usize {
        STATE_NEW_SAD_INFO_HEADER_LEN + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NewSadInfoMessageBuffer::new(buffer);
        buffer.set_flags(self.flags);
        self.nlas.as_slice().emit(&mut buffer.attributes_mut());
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NewSadInfoMessageBuffer<&'a T>> for NewSadInfoMessage {
    fn parse(buf: &NewSadInfoMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(NewSadInfoMessage {
            flags: buf.flags(),
            nlas: Vec::<SadInfoAttrs>::parse(buf)
                .context("failed to parse state new SAD info message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NewSadInfoMessageBuffer<&'a T>> for Vec<SadInfoAttrs> {
    fn parse(buf: &NewSadInfoMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(SadInfoAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct GetSadInfoMessage {
    pub flags: u32,
}

impl Emitable for GetSadInfoMessage {
    fn buffer_len(&self) -> usize {
        STATE_GET_SAD_INFO_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = GetSadInfoMessageBuffer::new(buffer);
        buffer.set_flags(self.flags);
    }
}

impl<T: AsRef<[u8]>> Parseable<GetSadInfoMessageBuffer<T>> for GetSadInfoMessage {
    fn parse(buf: &GetSadInfoMessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(GetSadInfoMessage { flags: buf.flags() })
    }
}
