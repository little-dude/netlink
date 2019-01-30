use crate::{DecodeError, Index, NlaBuffer, NlasIterator, Rest};

const FAMILY: Index = 0;
// some padding in between
const ATTRIBUTES: Rest = 4..;

pub const NEIGHBOUR_TABLE_HEADER_LEN: usize = ATTRIBUTES.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourTableBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NeighbourTableBuffer<T> {
    pub fn new(buffer: T) -> NeighbourTableBuffer<T> {
        NeighbourTableBuffer { buffer }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let packet = Self::new(buffer);
        packet.check_buffer_length()?;
        Ok(packet)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < NEIGHBOUR_TABLE_HEADER_LEN {
            Err(format!(
                "invalid NeighbourTableBuffer: length is {} but NeighbourTableBuffer are at least {} bytes",
                len, NEIGHBOUR_TABLE_HEADER_LEN
            )
            .into())
        } else {
            Ok(())
        }
    }
    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[FAMILY]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NeighbourTableBuffer<&'a T> {
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NeighbourTableBuffer<&'a mut T> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighbourTableBuffer<T> {
    pub fn set_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value
    }
}
