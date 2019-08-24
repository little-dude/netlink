use byteorder::{ByteOrder, NativeEndian};

use crate::{
    rtnl::{
        traits::{Emitable, Parseable},
        Field,
    },
    DecodeError,
};

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkIcmp6Stats {
    pub num: i64,
    pub in_msgs: i64,
    pub in_errors: i64,
    pub out_msgs: i64,
    pub out_errors: i64,
    pub csum_errors: i64,
}

const NUM: Field = 0..8;
const IN_MSGS: Field = 8..16;
const IN_ERRORS: Field = 16..24;
const OUT_MSGS: Field = 24..32;
const OUT_ERRORS: Field = 32..40;
const CSUM_ERRORS: Field = 40..48;

pub const LINK_ICMP6_STATS_LEN: usize = CSUM_ERRORS.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkIcmp6StatsBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkIcmp6StatsBuffer<T> {
    pub fn new(buffer: T) -> Self {
        LinkIcmp6StatsBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_ICMP6_STATS_LEN {
            return Err(format!(
                "invalid LinkIcmp6StatsBuffer buffer: length is {} instead of {}",
                len, LINK_ICMP6_STATS_LEN,
            )
            .into());
        }
        Ok(())
    }

    pub fn num(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[NUM])
    }

    pub fn in_msgs(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_MSGS])
    }

    pub fn in_errors(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_ERRORS])
    }

    pub fn out_msgs(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_MSGS])
    }

    pub fn out_errors(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_ERRORS])
    }

    pub fn csum_errors(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[CSUM_ERRORS])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkIcmp6StatsBuffer<T> {
    pub fn set_num(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[NUM], value)
    }

    pub fn set_in_msgs(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_MSGS], value)
    }

    pub fn set_in_errors(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_ERRORS], value)
    }

    pub fn set_out_msgs(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_MSGS], value)
    }

    pub fn set_out_errors(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_ERRORS], value)
    }

    pub fn set_csum_errors(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[CSUM_ERRORS], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkIcmp6Stats> for LinkIcmp6StatsBuffer<T> {
    fn parse(&self) -> Result<LinkIcmp6Stats, DecodeError> {
        Ok(LinkIcmp6Stats {
            num: self.num(),
            in_msgs: self.in_msgs(),
            in_errors: self.in_errors(),
            out_msgs: self.out_msgs(),
            out_errors: self.out_errors(),
            csum_errors: self.csum_errors(),
        })
    }
}

impl Emitable for LinkIcmp6Stats {
    fn buffer_len(&self) -> usize {
        LINK_ICMP6_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkIcmp6StatsBuffer::new(buffer);
        buffer.set_num(self.num);
        buffer.set_in_msgs(self.in_msgs);
        buffer.set_in_errors(self.in_errors);
        buffer.set_out_msgs(self.out_msgs);
        buffer.set_out_errors(self.out_errors);
        buffer.set_csum_errors(self.csum_errors);
    }
}
