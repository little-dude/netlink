use failure::ResultExt;

use crate::{
    nlas::neighbour::Nla,
    traits::{Emitable, Parseable},
    DecodeError, NeighbourHeader, NeighbourMessageBuffer,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourMessage {
    pub header: NeighbourHeader,
    pub nlas: Vec<Nla>,
}

impl Emitable for NeighbourMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourMessageBuffer<&'a T>> for NeighbourMessage {
    fn parse(buf: &NeighbourMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(NeighbourMessage {
            header: NeighbourHeader::parse(&buf)
                .context("failed to parse neighbour message header")?,
            nlas: Vec::<Nla>::parse(&buf).context("failed to parse neighbour message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourMessageBuffer<&'a T>> for Vec<Nla> {
    fn parse(buf: &NeighbourMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
