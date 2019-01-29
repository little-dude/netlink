use failure::ResultExt;

use super::{NsIdBuffer, NsIdNla};
use crate::{DecodeError, Emitable, NsIdHeader, Parseable};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NsIdMessage {
    pub header: NsIdHeader,
    pub nlas: Vec<NsIdNla>,
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NsIdMessage> for NsIdBuffer<&'buffer T> {
    fn parse(&self) -> Result<NsIdMessage, DecodeError> {
        Ok(NsIdMessage {
            header: self
                .parse()
                .context("failed to parse nsid message header")?,
            nlas: self.parse().context("failed to parse nsid message NLAs")?,
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<NsIdNla>> for NsIdBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<NsIdNla>, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}

impl Emitable for NsIdMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}
