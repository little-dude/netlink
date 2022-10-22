// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Replay {
    pub oseq: u32,
    pub seq: u32,
    pub bitmap: u32,
}

pub const XFRM_REPLAY_LEN: usize = 12;

buffer!(ReplayBuffer(XFRM_REPLAY_LEN) {
    oseq: (u32, 0..4),
    seq: (u32, 4..8),
    bitmap: (u32, 8..12)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<ReplayBuffer<&T>> for Replay {
    fn parse(buf: &ReplayBuffer<&T>) -> Result<Self, DecodeError> {
        Ok(Replay {
            oseq: buf.oseq(),
            seq: buf.seq(),
            bitmap: buf.bitmap(),
        })
    }
}

impl Emitable for Replay {
    fn buffer_len(&self) -> usize {
        XFRM_REPLAY_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = ReplayBuffer::new(buffer);
        buffer.set_oseq(self.oseq);
        buffer.set_seq(self.seq);
        buffer.set_bitmap(self.bitmap);
    }
}
