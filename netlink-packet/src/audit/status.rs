use byteorder::{ByteOrder, NativeEndian};

use {DecodeError, Emitable, Parseable};

pub const AUDIT_STATUS_BUFFER_LEN: usize = 40;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct StatusMessage {
    /// Bit mask for valid entries
    mask: u32,
    enabled: u32,
    /// Failure-to-log action
    failure: u32,
    /// PID of auditd process
    pid: u32,
    /// Message rate limit (per second)
    rate_limiting: u32,
    /// Waiting messages limit
    backlog_limit: u32,
    /// Messages lost
    lost: u32,
    /// Messages waiting in queue
    backlog: u32,
    /// bitmap of kernel audit features
    feature_bitmap: u32,
    /// Message queue wait timeout
    backlog_wait_time: u32,
}

impl StatusMessage {
    pub fn new() -> Self {
        StatusMessage::default()
    }

    pub fn mask(&self) -> u32 {
        self.mask
    }

    pub fn enabled(&self) -> bool {
        self.enabled == 1
    }

    pub fn failure(&self) -> u32 {
        self.failure
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn rate_limiting(&self) -> u32 {
        self.rate_limiting
    }

    pub fn backlog_limit(&self) -> u32 {
        self.backlog_limit
    }

    pub fn lost(&self) -> u32 {
        self.lost
    }

    pub fn backlog(&self) -> u32 {
        self.backlog
    }

    pub fn feature_bitmap(&self) -> u32 {
        self.feature_bitmap
    }

    pub fn backlog_wait_time(&self) -> u32 {
        self.backlog_wait_time
    }

    pub fn set_mask(mut self, value: u32) -> Self {
        self.mask = value;
        self
    }

    pub fn set_enabled(mut self, value: bool) -> Self {
        if value {
            self.enabled = 1;
        } else {
            self.enabled = 0;
        }
        self
    }

    pub fn set_failure(mut self, value: u32) -> Self {
        self.failure = value;
        self
    }

    pub fn set_pid(mut self, value: u32) -> Self {
        self.pid = value;
        self
    }

    pub fn set_rate_limiting(mut self, value: u32) -> Self {
        self.rate_limiting = value;
        self
    }

    pub fn set_backlog_limit(mut self, value: u32) -> Self {
        self.backlog_limit = value;
        self
    }

    pub fn set_lost(mut self, value: u32) -> Self {
        self.lost = value;
        self
    }

    pub fn set_backlog(mut self, value: u32) -> Self {
        self.backlog = value;
        self
    }

    pub fn set_feature_bitmap(mut self, value: u32) -> Self {
        self.feature_bitmap = value;
        self
    }

    pub fn set_backlog_wait_time(mut self, value: u32) -> Self {
        self.backlog_wait_time = value;
        self
    }

    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < AUDIT_STATUS_BUFFER_LEN {
            return Err(DecodeError::from(format!(
                "StatusMessage is {} bytes, buffer is only {} bytes: {:#x?}",
                AUDIT_STATUS_BUFFER_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(StatusMessage {
            mask: NativeEndian::read_u32(&buf[0..4]),
            enabled: NativeEndian::read_u32(&buf[4..8]),
            failure: NativeEndian::read_u32(&buf[8..12]),
            pid: NativeEndian::read_u32(&buf[12..16]),
            rate_limiting: NativeEndian::read_u32(&buf[16..20]),
            backlog_limit: NativeEndian::read_u32(&buf[20..24]),
            lost: NativeEndian::read_u32(&buf[24..28]),
            backlog: NativeEndian::read_u32(&buf[28..32]),
            feature_bitmap: NativeEndian::read_u32(&buf[32..36]),
            backlog_wait_time: NativeEndian::read_u32(&buf[36..40]),
        })
    }
    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < AUDIT_STATUS_BUFFER_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but StatusMessage is {} bytes",
                buf.len(),
                AUDIT_STATUS_BUFFER_LEN
            )));
        }
            NativeEndian::write_u32(&mut buf[0..4], self.mask);
            NativeEndian::write_u32(&mut buf[4..8], self.enabled);
            NativeEndian::write_u32(&mut buf[8..12], self.failure);
            NativeEndian::write_u32(&mut buf[12..16], self.pid);
            NativeEndian::write_u32(&mut buf[16..20], self.rate_limiting);
            NativeEndian::write_u32(&mut buf[20..24], self.backlog_limit);
            NativeEndian::write_u32(&mut buf[24..28], self.lost);
            NativeEndian::write_u32(&mut buf[28..32], self.backlog);
            NativeEndian::write_u32(&mut buf[32..36], self.feature_bitmap);
            NativeEndian::write_u32(&mut buf[36..40], self.backlog_wait_time);
        Ok(())
    }

}

impl Emitable for StatusMessage {
    fn buffer_len(&self) -> usize {
        AUDIT_STATUS_BUFFER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.to_bytes(buffer).expect("check the buffer length before calling emit_value()!")
    }
}

impl<T: AsRef<[u8]>> Parseable<StatusMessage> for T {
    fn parse(&self) -> Result<StatusMessage, DecodeError> {
        StatusMessage::from_bytes(self.as_ref())
    }
}
