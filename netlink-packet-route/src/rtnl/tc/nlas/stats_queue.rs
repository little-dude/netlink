use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

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

pub const TC_STATS_QUEUE_LEN: usize = 20;

buffer!(TcStatsQueueBuffer( TC_STATS_QUEUE_LEN) {
    qlen: (u32, 0..4),
    backlog: (u32, 4..8),
    drops: (u32, 8..12),
    requeues: (u32, 12..16),
    overlimits: (u32, 16..20),
});

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
