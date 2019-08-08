use byteorder::{ByteOrder, NativeEndian};

use crate::{
    traits::{Emitable, Parseable},
    DecodeError, Field,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NeighbourCacheInfo {
    pub confirmed: u32,
    pub used: u32,
    pub updated: u32,
    pub refcnt: u32,
}

const CONFIRMED: Field = 0..4;
const USED: Field = 4..8;
const UPDATED: Field = 8..12;
const REFCNT: Field = 12..16;
pub const NEIGHBOUR_CACHE_INFO_LEN: usize = REFCNT.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourCacheInfoBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NeighbourCacheInfoBuffer<T> {
    pub fn new(buffer: T) -> NeighbourCacheInfoBuffer<T> {
        NeighbourCacheInfoBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<NeighbourCacheInfoBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < NEIGHBOUR_CACHE_INFO_LEN {
            return Err(format!(
                "invalid NeighbourCacheInfoBuffer buffer: length is {} instead of {}",
                len, NEIGHBOUR_CACHE_INFO_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn confirmed(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[CONFIRMED])
    }

    pub fn used(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[USED])
    }

    pub fn updated(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[UPDATED])
    }

    pub fn refcnt(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[REFCNT])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighbourCacheInfoBuffer<T> {
    pub fn set_confirmed(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[CONFIRMED], value)
    }

    pub fn set_used(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[USED], value)
    }

    pub fn set_updated(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[UPDATED], value)
    }

    pub fn set_refcnt(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[REFCNT], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<NeighbourCacheInfo> for NeighbourCacheInfoBuffer<T> {
    fn parse(&self) -> Result<NeighbourCacheInfo, DecodeError> {
        self.check_buffer_length()?;
        Ok(NeighbourCacheInfo {
            confirmed: self.confirmed(),
            used: self.used(),
            updated: self.updated(),
            refcnt: self.refcnt(),
        })
    }
}

impl Emitable for NeighbourCacheInfo {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_CACHE_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NeighbourCacheInfoBuffer::new(buffer);
        buffer.set_confirmed(self.confirmed);
        buffer.set_used(self.used);
        buffer.set_updated(self.updated);
        buffer.set_refcnt(self.refcnt);
    }
}
