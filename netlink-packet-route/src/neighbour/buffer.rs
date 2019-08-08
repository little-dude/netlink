use byteorder::{ByteOrder, NativeEndian};

use crate::{
    nla::{NlaBuffer, NlasIterator},
    DecodeError, Field, Index, Rest,
};

use super::header::*;

const FAMILY: Index = 0;
const IFINDEX: Field = 4..8;
const STATE: Field = 8..10;
const FLAGS: Index = 10;
const TYPE: Index = 11;
const ATTRIBUTES: Rest = 12..;

pub const NEIGHBOUR_HEADER_LEN: usize = ATTRIBUTES.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NeighbourBuffer<T> {
    pub fn new(buffer: T) -> NeighbourBuffer<T> {
        NeighbourBuffer { buffer }
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
        if len < NEIGHBOUR_HEADER_LEN {
            Err(format!(
                "invalid NeighbourBuffer: length is {} but NeighbourBuffer are at least {} bytes",
                len, NEIGHBOUR_HEADER_LEN
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

    pub fn ifindex(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[IFINDEX])
    }

    pub fn state(&self) -> NeighbourState {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[STATE]).into()
    }

    pub fn flags(&self) -> NeighbourFlags {
        let data = self.buffer.as_ref();
        data[FLAGS].into()
    }

    pub fn ntype(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[TYPE]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NeighbourBuffer<&'a T> {
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NeighbourBuffer<&'a mut T> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighbourBuffer<T> {
    pub fn set_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value
    }

    pub fn set_ifindex(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IFINDEX], value)
    }

    pub fn set_state(&mut self, value: NeighbourState) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[STATE], value.into())
    }

    pub fn set_flags(&mut self, value: NeighbourFlags) {
        let data = self.buffer.as_mut();
        data[FLAGS] = value.into()
    }

    pub fn set_ntype(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[TYPE] = value
    }
}
