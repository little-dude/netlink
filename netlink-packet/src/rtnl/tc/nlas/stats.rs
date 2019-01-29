use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

/// Generic queue statistics
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcStats {
    /// Number of enqueued bytes
    pub bytes: u64,
    /// Number of enqueued packets
    pub packets: u32,
    /// Packets dropped because of lack of resources
    pub drops: u32,
    /// Number of throttle events when this flow goes out of allocated bandwidth
    pub overlimits: u32,
    /// Current flow byte rate
    pub bps: u32,
    /// Current flow packet rate
    pub pps: u32,
    pub qlen: u32,
    pub backlog: u32,
}

const BYTES: Field = 0..8;
const PACKETS: Field = 8..12;
const DROPS: Field = 12..16;
const OVERLIMITS: Field = 16..20;
const BPS: Field = 20..24;
const PPS: Field = 24..28;
const QLEN: Field = 28..32;
const BACKLOG: Field = 32..36;
pub const TC_STATS_LEN: usize = BACKLOG.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcStatsBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> TcStatsBuffer<T> {
    pub fn new(buffer: T) -> TcStatsBuffer<T> {
        TcStatsBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<TcStatsBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < TC_STATS_LEN {
            return Err(format!(
                "invalid TcStatsBuffer buffer: length is {} instead of {}",
                len, TC_STATS_LEN
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

    pub fn drops(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[DROPS])
    }

    pub fn overlimits(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[OVERLIMITS])
    }

    pub fn bps(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BPS])
    }

    pub fn pps(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[PPS])
    }

    pub fn qlen(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[QLEN])
    }

    pub fn backlog(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BACKLOG])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> TcStatsBuffer<T> {
    pub fn set_bytes(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[BYTES], value)
    }

    pub fn set_packets(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[PACKETS], value)
    }

    pub fn set_drops(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[DROPS], value)
    }

    pub fn set_overlimits(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[OVERLIMITS], value)
    }

    pub fn set_bps(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BPS], value)
    }

    pub fn set_pps(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[PPS], value)
    }

    pub fn set_qlen(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[QLEN], value)
    }

    pub fn set_backlog(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BACKLOG], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<TcStats> for TcStatsBuffer<T> {
    fn parse(&self) -> Result<TcStats, DecodeError> {
        self.check_buffer_length()?;
        Ok(TcStats {
            bytes: self.bytes(),
            packets: self.packets(),
            drops: self.drops(),
            overlimits: self.overlimits(),
            bps: self.bps(),
            pps: self.pps(),
            qlen: self.qlen(),
            backlog: self.backlog(),
        })
    }
}

impl Emitable for TcStats {
    fn buffer_len(&self) -> usize {
        TC_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TcStatsBuffer::new(buffer);
        buffer.set_bytes(self.bytes);
        buffer.set_packets(self.packets);
        buffer.set_drops(self.drops);
        buffer.set_overlimits(self.overlimits);
        buffer.set_bps(self.bps);
        buffer.set_pps(self.pps);
        buffer.set_qlen(self.qlen);
        buffer.set_backlog(self.backlog);
    }
}
