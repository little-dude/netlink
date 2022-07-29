// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    GetSpdInfoMessageBuffer,
    NewSpdInfoMessageBuffer,
    POLICY_GET_SPD_INFO_HEADER_LEN,
    POLICY_NEW_SPD_INFO_HEADER_LEN,
    SpdInfoAttrs,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewSpdInfoMessage {
    pub flags: u32,
    pub nlas: Vec<SpdInfoAttrs>
}

impl Emitable for NewSpdInfoMessage {
    fn buffer_len(&self) -> usize {
        POLICY_NEW_SPD_INFO_HEADER_LEN + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NewSpdInfoMessageBuffer::new(buffer);
        buffer.set_flags(self.flags);
        self.nlas
            .as_slice()
            .emit(&mut buffer.attributes_mut());
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NewSpdInfoMessageBuffer<&'a T>> for NewSpdInfoMessage {
    fn parse(buf: &NewSpdInfoMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(NewSpdInfoMessage {
            flags: buf.flags(),
            nlas: Vec::<SpdInfoAttrs>::parse(buf).context("failed to parse policy new SPD info message NLAs")?
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NewSpdInfoMessageBuffer<&'a T>> for Vec<SpdInfoAttrs> {
    fn parse(buf: &NewSpdInfoMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(SpdInfoAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct GetSpdInfoMessage {
    pub flags: u32,
}

impl Emitable for GetSpdInfoMessage {
    fn buffer_len(&self) -> usize {
        POLICY_GET_SPD_INFO_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = GetSpdInfoMessageBuffer::new(buffer);
        buffer.set_flags(self.flags);
    }
}

impl<T: AsRef<[u8]>> Parseable<GetSpdInfoMessageBuffer<T>> for GetSpdInfoMessage {
    fn parse(buf: &GetSpdInfoMessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(GetSpdInfoMessage {
            flags: buf.flags()
        })
    }
}
