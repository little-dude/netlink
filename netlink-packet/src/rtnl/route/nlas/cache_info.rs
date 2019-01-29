use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RouteCacheInfo {
    pub clntref: u32,
    pub last_use: u32,
    pub expires: u32,
    pub error: u32,
    pub used: u32,
    pub id: u32,
    pub ts: u32,
    pub ts_age: u32,
}

const CLNTREF: Field = 0..4;
const LAST_USE: Field = 4..8;
const EXPIRES: Field = 8..12;
const ERROR: Field = 12..16;
const USED: Field = 16..20;
const ID: Field = 20..24;
const TS: Field = 24..28;
const TS_AGE: Field = 28..32;

pub const ROUTE_CACHE_INFO_LEN: usize = TS_AGE.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteCacheInfoBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RouteCacheInfoBuffer<T> {
    pub fn new(buffer: T) -> RouteCacheInfoBuffer<T> {
        RouteCacheInfoBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<RouteCacheInfoBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < ROUTE_CACHE_INFO_LEN {
            return Err(format!(
                "invalid RouteCacheInfoBuffer buffer: length is {} instead of {}",
                len, ROUTE_CACHE_INFO_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn clntref(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[CLNTREF])
    }

    pub fn last_use(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[LAST_USE])
    }

    pub fn expires(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[EXPIRES])
    }

    pub fn error(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[ERROR])
    }

    pub fn used(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[USED])
    }

    pub fn id(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[ID])
    }

    pub fn ts(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TS])
    }

    pub fn ts_age(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TS_AGE])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RouteCacheInfoBuffer<T> {
    pub fn set_clntref(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[CLNTREF], value)
    }

    pub fn set_last_use(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[LAST_USE], value)
    }

    pub fn set_expires(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[EXPIRES], value)
    }

    pub fn set_error(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[ERROR], value)
    }

    pub fn set_used(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[USED], value)
    }

    pub fn set_id(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[ID], value)
    }

    pub fn set_ts(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TS], value)
    }

    pub fn set_ts_age(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TS_AGE], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<RouteCacheInfo> for RouteCacheInfoBuffer<T> {
    fn parse(&self) -> Result<RouteCacheInfo, DecodeError> {
        Ok(RouteCacheInfo {
            clntref: self.clntref(),
            last_use: self.last_use(),
            expires: self.expires(),
            error: self.error(),
            used: self.used(),
            id: self.id(),
            ts: self.ts(),
            ts_age: self.ts_age(),
        })
    }
}

impl Emitable for RouteCacheInfo {
    fn buffer_len(&self) -> usize {
        ROUTE_CACHE_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = RouteCacheInfoBuffer::new(buffer);
        buffer.set_clntref(self.clntref);
        buffer.set_last_use(self.last_use);
        buffer.set_expires(self.expires);
        buffer.set_error(self.error);
        buffer.set_used(self.used);
        buffer.set_id(self.id);
        buffer.set_ts(self.ts);
        buffer.set_ts_age(self.ts_age);
    }
}
