use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

const MASK: Field = 0..4;
const ENABLED: Field = 4..8;
const FAILURE: Field = 8..12;
const PID: Field = 12..16;
const RATE_LIMITING: Field = 16..20;
const BACKLOG_LIMIT: Field = 20..24;
const LOST: Field = 24..28;
const BACKLOG: Field = 28..32;
const FEATURE_BITMAP: Field = 32..36;
const BACKLOG_WAIT_TIME: Field = 36..40;
pub const STATUS_MESSAGE_LEN: usize = BACKLOG_WAIT_TIME.end;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct StatusMessage {
    /// Bit mask for valid entries
    pub mask: u32,
    pub enabled: u32,
    /// Failure-to-log action
    pub failure: u32,
    /// PID of auditd process
    pub pid: u32,
    /// Message rate limit (per second)
    pub rate_limiting: u32,
    /// Waiting messages limit
    pub backlog_limit: u32,
    /// Messages lost
    pub lost: u32,
    /// Messages waiting in queue
    pub backlog: u32,
    /// bitmap of kernel audit features
    pub feature_bitmap: u32,
    /// Message queue wait timeout
    pub backlog_wait_time: u32,
}

impl StatusMessage {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StatusMessageBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> StatusMessageBuffer<T> {
    pub fn new(buffer: T) -> StatusMessageBuffer<T> {
        StatusMessageBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<StatusMessageBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < STATUS_MESSAGE_LEN {
            return Err(format!(
                "invalid StatusMessageBuffer buffer: length is {} instead of {}",
                len, STATUS_MESSAGE_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn mask(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[MASK])
    }

    pub fn enabled(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[ENABLED])
    }

    pub fn failure(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[FAILURE])
    }

    pub fn pid(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[PID])
    }

    pub fn rate_limiting(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RATE_LIMITING])
    }

    pub fn backlog_limit(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BACKLOG_LIMIT])
    }

    pub fn lost(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[LOST])
    }

    pub fn backlog(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BACKLOG])
    }

    pub fn feature_bitmap(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[FEATURE_BITMAP])
    }

    pub fn backlog_wait_time(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BACKLOG_WAIT_TIME])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> StatusMessageBuffer<T> {
    pub fn set_mask(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[MASK], value)
    }

    pub fn set_enabled(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[ENABLED], value)
    }

    pub fn set_failure(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[FAILURE], value)
    }

    pub fn set_pid(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[PID], value)
    }

    pub fn set_rate_limiting(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RATE_LIMITING], value)
    }

    pub fn set_backlog_limit(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BACKLOG_LIMIT], value)
    }

    pub fn set_lost(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[LOST], value)
    }

    pub fn set_backlog(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BACKLOG], value)
    }

    pub fn set_feature_bitmap(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[FEATURE_BITMAP], value)
    }

    pub fn set_backlog_wait_time(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BACKLOG_WAIT_TIME], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<StatusMessage> for StatusMessageBuffer<T> {
    fn parse(&self) -> Result<StatusMessage, DecodeError> {
        self.check_buffer_length()?;
        Ok(StatusMessage {
            mask: self.mask(),
            enabled: self.enabled(),
            failure: self.failure(),
            pid: self.pid(),
            rate_limiting: self.rate_limiting(),
            backlog_limit: self.backlog_limit(),
            lost: self.lost(),
            backlog: self.backlog(),
            feature_bitmap: self.feature_bitmap(),
            backlog_wait_time: self.backlog_wait_time(),
        })
    }
}

impl Emitable for StatusMessage {
    fn buffer_len(&self) -> usize {
        STATUS_MESSAGE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = StatusMessageBuffer::new(buffer);
        buffer.set_mask(self.mask);
        buffer.set_enabled(self.enabled);
        buffer.set_failure(self.failure);
        buffer.set_pid(self.pid);
        buffer.set_rate_limiting(self.rate_limiting);
        buffer.set_backlog_limit(self.backlog_limit);
        buffer.set_lost(self.lost);
        buffer.set_backlog(self.backlog);
        buffer.set_feature_bitmap(self.feature_bitmap);
        buffer.set_backlog_wait_time(self.backlog_wait_time);
    }
}
