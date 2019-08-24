use crate::{
    rtnl::{
        neighbour_table::{nlas::NeighbourTableNla, NeighbourTableBuffer, NeighbourTableHeader},
        traits::{Emitable, Parseable},
    },
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourTableMessage {
    pub header: NeighbourTableHeader,
    pub nlas: Vec<NeighbourTableNla>,
}

impl Emitable for NeighbourTableMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NeighbourTableMessage>
    for NeighbourTableBuffer<&'buffer T>
{
    fn parse(&self) -> Result<NeighbourTableMessage, DecodeError> {
        Ok(NeighbourTableMessage {
            header: self.parse()?,
            nlas: self.parse()?,
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<NeighbourTableNla>>
    for NeighbourTableBuffer<&'buffer T>
{
    fn parse(&self) -> Result<Vec<NeighbourTableNla>, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}
