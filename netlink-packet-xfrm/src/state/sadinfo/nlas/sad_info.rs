// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SadHInfo {
    pub sadhcnt: u32,
    pub sadhmcnt: u32,
}

pub const XFRM_SAD_HINFO_LEN: usize = 8;

buffer!(SadHInfoBuffer(XFRM_SAD_HINFO_LEN) {
    sadhcnt: (u32, 0..4),
    sadhmcnt: (u32, 4..8)
});

impl<T: AsRef<[u8]>> Parseable<SadHInfoBuffer<T>> for SadHInfo {
    fn parse(buf: &SadHInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(SadHInfo {
            sadhcnt: buf.sadhcnt(),
            sadhmcnt: buf.sadhmcnt(),
        })
    }
}

impl Emitable for SadHInfo {
    fn buffer_len(&self) -> usize {
        XFRM_SAD_HINFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = SadHInfoBuffer::new(buffer);
        buffer.set_sadhcnt(self.sadhcnt);
        buffer.set_sadhmcnt(self.sadhmcnt);
    }
}
