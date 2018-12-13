use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

/// Queuing statistics
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcStatsQueue {
    /// queue length
    pub qlen: u32,
    /// backlog size of queue
    pub backlog: u32,
    /// number of dropped packets
    pub drops: u32,
    /// number of requeues
    pub requeues: u32,
    /// number of enqueues over the limit
    pub overlimits: u32,
}

const QLEN: Field = 0..4;
const BACKLOG: Field = 4..8;
const DROPS: Field = 8..12;
const REQUEUES: Field = 12..16;
const OVERLIMITS: Field = 16..20;

pub const TC_STATS_QUEUE_LEN: usize = OVERLIMITS.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcStatsQueueBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> TcStatsQueueBuffer<T> {
    pub fn new(buffer: T) -> TcStatsQueueBuffer<T> {
        TcStatsQueueBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<TcStatsQueueBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < TC_STATS_QUEUE_LEN {
            return Err(format!(
                "invalid TcStatsQueueBuffer buffer: length is {} instead of {}",
                len, TC_STATS_QUEUE_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn qlen(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[QLEN])
    }

    pub fn backlog(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BACKLOG])
    }

    pub fn drops(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[DROPS])
    }

    pub fn requeues(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[REQUEUES])
    }

    pub fn overlimits(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[OVERLIMITS])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> TcStatsQueueBuffer<T> {
    pub fn set_qlen(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[QLEN], value)
    }

    pub fn set_backlog(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BACKLOG], value)
    }

    pub fn set_drops(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[DROPS], value)
    }

    pub fn set_requeues(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[REQUEUES], value)
    }

    pub fn set_overlimits(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[OVERLIMITS], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<TcStatsQueue> for TcStatsQueueBuffer<T> {
    fn parse(&self) -> Result<TcStatsQueue, DecodeError> {
        self.check_buffer_length()?;
        Ok(TcStatsQueue {
            qlen: self.qlen(),
            backlog: self.backlog(),
            drops: self.drops(),
            requeues: self.requeues(),
            overlimits: self.overlimits(),
        })
    }
}

impl Emitable for TcStatsQueue {
    fn buffer_len(&self) -> usize {
        TC_STATS_QUEUE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TcStatsQueueBuffer::new(buffer);
        buffer.set_qlen(self.qlen);
        buffer.set_backlog(self.backlog);
        buffer.set_drops(self.drops);
        buffer.set_requeues(self.requeues);
        buffer.set_overlimits(self.overlimits);
    }
}
