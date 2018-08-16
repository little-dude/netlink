use crate::{DecodeError, Emitable, Parseable};

use super::buffer::{NeighbourTableBuffer, NEIGHBOUR_TABLE_HEADER_LEN};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourTableHeader {
    pub family: u8,
}

impl<T: AsRef<[u8]>> Parseable<NeighbourTableHeader> for NeighbourTableBuffer<T> {
    fn parse(&self) -> Result<NeighbourTableHeader, DecodeError> {
        Ok(NeighbourTableHeader {
            family: self.family(),
        })
    }
}

impl Emitable for NeighbourTableHeader {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_TABLE_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = NeighbourTableBuffer::new(buffer);
        packet.set_family(self.family);
    }
}
