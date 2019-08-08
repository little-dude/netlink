use crate::{
    neighbour::{nlas::NeighbourNla, NeighbourBuffer, NeighbourHeader},
    traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourMessage {
    pub header: NeighbourHeader,
    pub nlas: Vec<NeighbourNla>,
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

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NeighbourMessage>
    for NeighbourBuffer<&'buffer T>
{
    fn parse(&self) -> Result<NeighbourMessage, DecodeError> {
        Ok(NeighbourMessage {
            header: self.parse()?,
            nlas: self.parse()?,
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<NeighbourNla>>
    for NeighbourBuffer<&'buffer T>
{
    fn parse(&self) -> Result<Vec<NeighbourNla>, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}
