use super::{RouteBuffer, RouteHeader, RouteNla};
use crate::{DecodeError, Emitable, Parseable};
use failure::ResultExt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteMessage {
    pub header: RouteHeader,
    pub nlas: Vec<RouteNla>,
}

impl Emitable for RouteMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<RouteMessage> for RouteBuffer<&'buffer T> {
    fn parse(&self) -> Result<RouteMessage, DecodeError> {
        Ok(RouteMessage {
            header: self
                .parse()
                .context("failed to parse route message header")?,
            nlas: self.parse().context("failed to parse route message NLAs")?,
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<RouteNla>> for RouteBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<RouteNla>, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}
