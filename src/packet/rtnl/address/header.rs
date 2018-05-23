use byteorder::{ByteOrder, NativeEndian};

use packet::field;

const FAMILY: field::Index = 0;
const PREFIX_LEN: field::Index = 1;
const FLAGS: field::Index = 2;
const SCOPE: field::Index = 3;
const INDEX: field::Field = 4..8;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressMessageBuffer<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> AddressMessageBuffer<T> {
    pub fn new(buffer: T) -> AddressMessageBuffer<T> {
        AddressMessageBuffer { buffer }
    }

    pub fn into_inner(self) -> T {
        self.buffer
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

impl<T: AsRef<[u8]> + AsMut<[u8]>> AddressMessageBuffer<T> {
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
