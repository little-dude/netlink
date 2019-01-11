use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RouteMfcStats {
    pub packets: u64,
    pub bytes: u64,
    pub wrong_if: u64,
}
const PACKETS: Field = 0..8;
const BYTES: Field = 8..16;
const WRONG_IF: Field = 16..24;

pub const ROUTE_MFC_STATS_LEN: usize = WRONG_IF.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteMfcStatsBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RouteMfcStatsBuffer<T> {
    pub fn new(buffer: T) -> RouteMfcStatsBuffer<T> {
        RouteMfcStatsBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<RouteMfcStatsBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < ROUTE_MFC_STATS_LEN {
            return Err(format!(
                "invalid RouteMfcStatsBuffer buffer: length is {} instead of {}",
                len, ROUTE_MFC_STATS_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn packets(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[PACKETS])
    }

    pub fn bytes(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[BYTES])
    }

    pub fn wrong_if(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[WRONG_IF])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RouteMfcStatsBuffer<T> {
    pub fn set_packets(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[PACKETS], value)
    }

    pub fn set_bytes(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[BYTES], value)
    }

    pub fn set_wrong_if(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[WRONG_IF], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<RouteMfcStats> for RouteMfcStatsBuffer<T> {
    fn parse(&self) -> Result<RouteMfcStats, DecodeError> {
        self.check_buffer_length()?;
        Ok(RouteMfcStats {
            packets: self.packets(),
            bytes: self.bytes(),
            wrong_if: self.wrong_if(),
        })
    }
}

impl Emitable for RouteMfcStats {
    fn buffer_len(&self) -> usize {
        ROUTE_MFC_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = RouteMfcStatsBuffer::new(buffer);
        buffer.set_packets(self.packets);
        buffer.set_bytes(self.bytes);
        buffer.set_wrong_if(self.wrong_if);
    }
}
