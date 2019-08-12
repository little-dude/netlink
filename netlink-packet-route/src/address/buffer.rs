use byteorder::{ByteOrder, NativeEndian};

use crate::{
    nla::{NlaBuffer, NlasIterator},
    DecodeError, Field, Index, Rest,
};

const FAMILY: Index = 0;
const PREFIX_LEN: Index = 1;
const FLAGS: Index = 2;
const SCOPE: Index = 3;
const INDEX: Field = 4..8;
const ATTRIBUTES: Rest = 8..;

pub const ADDRESS_HEADER_LEN: usize = ATTRIBUTES.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> AddressBuffer<T> {
    pub fn new(buffer: T) -> Self {
        AddressBuffer { buffer }
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
        if len < ADDRESS_HEADER_LEN {
            Err(format!(
                "invalid AddressBuffer: length is {} but AddressBuffer are at least {} bytes",
                len, ADDRESS_HEADER_LEN
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

    pub fn prefix_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[PREFIX_LEN]
    }

    pub fn flags(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[FLAGS]
    }

    pub fn scope(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SCOPE]
    }

    pub fn index(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[INDEX])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> AddressBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> AddressBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AddressBuffer<T> {
    pub fn set_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value
    }

    pub fn set_prefix_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[PREFIX_LEN] = value
    }

    pub fn set_flags(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[FLAGS] = value
    }

    pub fn set_scope(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[SCOPE] = value
    }

    pub fn set_index(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[INDEX], value)
    }
}
