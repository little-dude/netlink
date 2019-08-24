use byteorder::{ByteOrder, NativeEndian};

use crate::{
    rtnl::{
        traits::{Emitable, Parseable},
        Field,
    },
    DecodeError,
};

const MAX_REASM_LEN: Field = 0..4;
const TSTAMP: Field = 4..8;
const REACHABLE_TIME: Field = 8..12;
const RETRANS_TIME: Field = 12..16;
pub const LINK_INET6_CACHE_INFO_LEN: usize = RETRANS_TIME.end;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInet6CacheInfo {
    pub max_reasm_len: i32,
    pub tstamp: i32,
    pub reachable_time: i32,
    pub retrans_time: i32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkInet6CacheInfoBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkInet6CacheInfoBuffer<T> {
    pub fn new(buffer: T) -> LinkInet6CacheInfoBuffer<T> {
        LinkInet6CacheInfoBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<LinkInet6CacheInfoBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_INET6_CACHE_INFO_LEN {
            return Err(format!(
                "invalid LinkInet6CacheInfoBuffer buffer: length is {} instead of {}",
                len, LINK_INET6_CACHE_INFO_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }
    pub fn max_reasm_len(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[MAX_REASM_LEN])
    }

    pub fn tstamp(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[TSTAMP])
    }

    pub fn reachable_time(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[REACHABLE_TIME])
    }

    pub fn retrans_time(&self) -> i32 {
        NativeEndian::read_i32(&self.buffer.as_ref()[RETRANS_TIME])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkInet6CacheInfoBuffer<T> {
    pub fn set_max_reasm_len(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[MAX_REASM_LEN], value)
    }

    pub fn set_tstamp(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[TSTAMP], value)
    }

    pub fn set_reachable_time(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[REACHABLE_TIME], value)
    }

    pub fn set_retrans_time(&mut self, value: i32) {
        NativeEndian::write_i32(&mut self.buffer.as_mut()[RETRANS_TIME], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkInet6CacheInfo> for LinkInet6CacheInfoBuffer<T> {
    fn parse(&self) -> Result<LinkInet6CacheInfo, DecodeError> {
        Ok(LinkInet6CacheInfo {
            max_reasm_len: self.max_reasm_len(),
            tstamp: self.tstamp(),
            reachable_time: self.reachable_time(),
            retrans_time: self.retrans_time(),
        })
    }
}

impl Emitable for LinkInet6CacheInfo {
    fn buffer_len(&self) -> usize {
        LINK_INET6_CACHE_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkInet6CacheInfoBuffer::new(buffer);
        buffer.set_max_reasm_len(self.max_reasm_len);
        buffer.set_tstamp(self.tstamp);
        buffer.set_reachable_time(self.reachable_time);
        buffer.set_retrans_time(self.retrans_time);
    }
}
