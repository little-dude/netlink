use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NeighbourTableConfig {
    pub key_len: u16,
    pub entry_size: u16,
    pub entries: u32,
    pub last_flush: u32,
    pub last_rand: u32,
    pub hash_rand: u32,
    pub hash_mask: u32,
    pub hash_chain_gc: u32,
    pub proxy_qlen: u32,
}

const KEY_LEN: Field = 0..2;
const ENTRY_SIZE: Field = 2..4;
const ENTRIES: Field = 4..8;
const LAST_FLUSH: Field = 8..12;
const LAST_RAND: Field = 12..16;
const HASH_RAND: Field = 16..20;
const HASH_MASK: Field = 20..24;
const HASH_CHAIN_GC: Field = 24..28;
const PROXY_QLEN: Field = 28..32;
pub const NEIGHBOUR_TABLE_CONFIG_LEN: usize = PROXY_QLEN.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourTableConfigBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NeighbourTableConfigBuffer<T> {
    pub fn new(buffer: T) -> NeighbourTableConfigBuffer<T> {
        NeighbourTableConfigBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<NeighbourTableConfigBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < NEIGHBOUR_TABLE_CONFIG_LEN {
            return Err(format!(
                "invalid NeighbourTableConfigBuffer buffer: length is {} instead of {}",
                len, NEIGHBOUR_TABLE_CONFIG_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn key_len(&self) -> u16 {
        NativeEndian::read_u16(&self.buffer.as_ref()[KEY_LEN])
    }

    pub fn entry_size(&self) -> u16 {
        NativeEndian::read_u16(&self.buffer.as_ref()[ENTRY_SIZE])
    }

    pub fn entries(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[ENTRIES])
    }

    pub fn last_flush(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[LAST_FLUSH])
    }

    pub fn last_rand(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[LAST_RAND])
    }

    pub fn hash_rand(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[HASH_RAND])
    }

    pub fn hash_mask(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[HASH_MASK])
    }

    pub fn hash_chain_gc(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[HASH_CHAIN_GC])
    }

    pub fn proxy_qlen(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[PROXY_QLEN])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighbourTableConfigBuffer<T> {
    pub fn set_key_len(&mut self, value: u16) {
        NativeEndian::write_u16(&mut self.buffer.as_mut()[KEY_LEN], value.into())
    }

    pub fn set_entry_size(&mut self, value: u16) {
        NativeEndian::write_u16(&mut self.buffer.as_mut()[ENTRY_SIZE], value.into())
    }

    pub fn set_entries(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[ENTRIES], value.into())
    }

    pub fn set_last_flush(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[LAST_FLUSH], value.into())
    }

    pub fn set_last_rand(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[LAST_RAND], value.into())
    }

    pub fn set_hash_rand(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[HASH_RAND], value.into())
    }

    pub fn set_hash_mask(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[HASH_MASK], value.into())
    }

    pub fn set_hash_chain_gc(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[HASH_CHAIN_GC], value.into())
    }

    pub fn set_proxy_qlen(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[PROXY_QLEN], value.into())
    }
}

impl<T: AsRef<[u8]>> Parseable<NeighbourTableConfig> for NeighbourTableConfigBuffer<T> {
    fn parse(&self) -> Result<NeighbourTableConfig, DecodeError> {
        self.check_buffer_length()?;
        Ok(NeighbourTableConfig {
            key_len: self.key_len(),
            entry_size: self.entry_size(),
            entries: self.entries(),
            last_flush: self.last_flush(),
            last_rand: self.last_rand(),
            hash_rand: self.hash_rand(),
            hash_mask: self.hash_mask(),
            hash_chain_gc: self.hash_chain_gc(),
            proxy_qlen: self.proxy_qlen(),
        })
    }
}

impl Emitable for NeighbourTableConfig {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_TABLE_CONFIG_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NeighbourTableConfigBuffer::new(buffer);
        buffer.set_key_len(self.key_len);
        buffer.set_entry_size(self.entry_size);
        buffer.set_entries(self.entries);
        buffer.set_last_flush(self.last_flush);
        buffer.set_last_rand(self.last_rand);
        buffer.set_hash_rand(self.hash_rand);
        buffer.set_hash_mask(self.hash_mask);
        buffer.set_hash_chain_gc(self.hash_chain_gc);
        buffer.set_proxy_qlen(self.proxy_qlen);
    }
}
