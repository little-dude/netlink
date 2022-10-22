// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{AllocSpiMessageBuffer, UserSpiInfo, UserSpiInfoBuffer, XfrmAttrs};

use netlink_packet_utils::{traits::*, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AllocSpiMessage {
    pub spi_info: UserSpiInfo,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for AllocSpiMessage {
    fn buffer_len(&self) -> usize {
        self.spi_info.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.spi_info.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.spi_info.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<AllocSpiMessageBuffer<&'a T>> for AllocSpiMessage {
    fn parse(buf: &AllocSpiMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let spi_info = UserSpiInfo::parse(&UserSpiInfoBuffer::new(&buf.spi_info()))
            .context("failed to parse state allocspi message spi info")?;
        Ok(AllocSpiMessage {
            spi_info,
            nlas: Vec::<XfrmAttrs>::parse(buf)
                .context("failed to parse state delget message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<AllocSpiMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &AllocSpiMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
