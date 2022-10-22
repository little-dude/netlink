// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Stats {
    pub replay_window: u32,
    pub replay: u32,
    pub integrity_failed: u32,
}

pub const XFRM_STATS_LEN: usize = 12;

buffer!(StatsBuffer(XFRM_STATS_LEN) {
    replay_window: (u32, 0..4),
    replay: (u32, 4..8),
    integrity_failed: (u32, 8..12)
});

impl<T: AsRef<[u8]>> Parseable<StatsBuffer<T>> for Stats {
    fn parse(buf: &StatsBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Stats {
            replay_window: buf.replay_window(),
            replay: buf.replay(),
            integrity_failed: buf.integrity_failed(),
        })
    }
}

impl Emitable for Stats {
    fn buffer_len(&self) -> usize {
        XFRM_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = StatsBuffer::new(buffer);
        buffer.set_replay_window(self.replay_window);
        buffer.set_replay(self.replay);
        buffer.set_integrity_failed(self.integrity_failed);
    }
}
