use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

/// Byte/Packet throughput statistics
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcStatsBasic {
    /// number of seen bytes
    pub bytes: u64,
    /// number of seen packets
    pub packets: u32,
}

const BYTES: Field = 0..8;
const PACKETS: Field = 8..12;
pub const TC_STATS_BASIC_LEN: usize = PACKETS.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcStatsBasicBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> TcStatsBasicBuffer<T> {
    pub fn new(buffer: T) -> TcStatsBasicBuffer<T> {
        TcStatsBasicBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<TcStatsBasicBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < TC_STATS_BASIC_LEN {
            return Err(format!(
                "invalid TcStatsBasicBuffer buffer: length is {} instead of {}",
                len, TC_STATS_BASIC_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn bytes(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[BYTES])
    }

    pub fn packets(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[PACKETS])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> TcStatsBasicBuffer<T> {
    pub fn set_bytes(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[BYTES], value)
    }

    pub fn set_packets(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[PACKETS], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<TcStatsBasic> for TcStatsBasicBuffer<T> {
    fn parse(&self) -> Result<TcStatsBasic, DecodeError> {
        self.check_buffer_length()?;
        Ok(TcStatsBasic {
            bytes: self.bytes(),
            packets: self.packets(),
        })
    }
}

impl Emitable for TcStatsBasic {
    fn buffer_len(&self) -> usize {
        TC_STATS_BASIC_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TcStatsBasicBuffer::new(buffer);
        buffer.set_bytes(self.bytes);
        buffer.set_packets(self.packets);
    }
}
