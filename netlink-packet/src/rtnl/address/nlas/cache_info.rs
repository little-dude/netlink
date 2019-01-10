use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AddressCacheInfo {
    pub ifa_preferred: i32,
    pub ifa_valid: i32,
    pub cstamp: i32,
    pub tstamp: i32,
}

const IFA_PREFERRED: Field = 0..4;
const IFA_VALID: Field = 4..8;
const CSTAMP: Field = 8..12;
const TSTAMP: Field = 12..16;

pub const ADDRESSS_CACHE_INFO_LEN: usize = TSTAMP.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressCacheInfoBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> AddressCacheInfoBuffer<T> {
    pub fn new(buffer: T) -> AddressCacheInfoBuffer<T> {
        AddressCacheInfoBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<AddressCacheInfoBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < ADDRESSS_CACHE_INFO_LEN {
            return Err(format!(
                "invalid AddressCacheInfoBuffer buffer: length is {} instead of {}",
                len, ADDRESSS_CACHE_INFO_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn ifa_preferred(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[IFA_PREFERRED])
    }

    pub fn ifa_valid(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[IFA_VALID])
    }

    pub fn cstamp(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[CSTAMP])
    }

    pub fn tstamp(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[TSTAMP])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AddressCacheInfoBuffer<T> {
    pub fn set_ifa_preferred(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[IFA_PREFERRED], value.into())
    }

    pub fn set_ifa_valid(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[IFA_VALID], value.into())
    }

    pub fn set_cstamp(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[CSTAMP], value.into())
    }

    pub fn set_tstamp(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[TSTAMP], value.into())
    }
}

impl<T: AsRef<[u8]>> Parseable<AddressCacheInfo> for AddressCacheInfoBuffer<T> {
    fn parse(&self) -> Result<AddressCacheInfo, DecodeError> {
        self.check_buffer_length()?;
        Ok(AddressCacheInfo {
            ifa_preferred: self.ifa_preferred(),
            ifa_valid: self.ifa_valid(),
            cstamp: self.cstamp(),
            tstamp: self.tstamp(),
        })
    }
}

impl Emitable for AddressCacheInfo {
    fn buffer_len(&self) -> usize {
        ADDRESSS_CACHE_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = AddressCacheInfoBuffer::new(buffer);
        buffer.set_ifa_preferred(self.ifa_preferred);
        buffer.set_ifa_valid(self.ifa_valid);
        buffer.set_cstamp(self.cstamp);
        buffer.set_tstamp(self.tstamp);
    }
}
