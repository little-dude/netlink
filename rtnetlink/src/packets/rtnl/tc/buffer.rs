use byteorder::{ByteOrder, NativeEndian};

use {Field, Index, NlaBuffer, NlasIterator, Rest, Result};

const FAMILY: Index = 0;
const PAD1: Index = 1;
const PAD2: Field = 2..4;
const INDEX: Field = 4..8;
const HANDLE: Field = 8..12;
const PARENT: Field = 12..16;
const INFO: Field = 16..20;
const ATTRIBUTES: Rest = 20..;

pub const TC_HEADER_LEN: usize = ATTRIBUTES.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> TcBuffer<T> {
    pub fn new(buffer: T) -> TcBuffer<T> {
        TcBuffer { buffer }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[FAMILY]
    }

    pub fn pad1(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[PAD1]
    }

    pub fn pad2(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[PAD2])
    }

    pub fn index(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[INDEX])
    }

    pub fn handle(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[HANDLE])
    }

    pub fn parent(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[PARENT])
    }

    pub fn info(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[INFO])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> TcBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> TcBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> TcBuffer<T> {
    pub fn set_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value
    }

    pub fn set_index(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_i32(&mut data[INDEX], value)
    }

    pub fn set_handle(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[HANDLE], value)
    }

    pub fn set_parent(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[PARENT], value)
    }

    pub fn set_info(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[INFO], value)
    }
}
