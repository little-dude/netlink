// SPDX-License-Identifier: MIT

use byteorder::{ByteOrder, NativeEndian};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

pub const XFRM_REPLAY_ESN_LEN: usize = 24;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ReplayEsn {
    pub bmp_len: u32,
    pub oseq: u32,
    pub seq: u32,
    pub oseq_hi: u32,
    pub seq_hi: u32,
    pub replay_window: u32,
    pub bmp: Vec<u32>,
}

buffer!(ReplayEsnBuffer(XFRM_REPLAY_ESN_LEN) {
    bmp_len: (u32, 0..4),
    oseq: (u32, 4..8),
    seq: (u32, 8..12),
    oseq_hi: (u32, 12..16),
    seq_hi: (u32, 16..20),
    replay_window: (u32, 20..24),
    bmp: (slice, 24..)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<ReplayEsnBuffer<&T>> for ReplayEsn {
    fn parse(buf: &ReplayEsnBuffer<&T>) -> Result<Self, DecodeError> {
        if buf.bmp().len() % 4 != 0 {
            return Err(DecodeError::from("invalid ReplayEsnBuffer bmp"));
        }
        let bmp = buf.bmp().chunks(4).map(NativeEndian::read_u32).collect();

        Ok(ReplayEsn {
            bmp_len: buf.bmp_len(),
            oseq: buf.oseq(),
            seq: buf.seq(),
            oseq_hi: buf.oseq_hi(),
            seq_hi: buf.seq_hi(),
            replay_window: buf.replay_window(),
            bmp,
        })
    }
}

impl Emitable for ReplayEsn {
    fn buffer_len(&self) -> usize {
        XFRM_REPLAY_ESN_LEN + self.bmp.len() * 4
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = ReplayEsnBuffer::new(buffer);
        buffer.set_bmp_len(self.bmp_len);
        buffer.set_oseq(self.oseq);
        buffer.set_seq(self.seq);
        buffer.set_oseq_hi(self.oseq_hi);
        buffer.set_seq_hi(self.seq_hi);
        buffer.set_replay_window(self.replay_window);
        for (i, v) in self.bmp.iter().enumerate() {
            NativeEndian::write_u32(&mut buffer.bmp_mut()[i * 4..], *v);
        }
    }
}
