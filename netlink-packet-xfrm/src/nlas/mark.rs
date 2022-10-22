// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Mark {
    pub value: u32,
    pub mask: u32,
}

pub const XFRM_MARK_LEN: usize = 8;

buffer!(MarkBuffer(XFRM_MARK_LEN) {
    value: (u32, 0..4),
    mask: (u32, 4..8)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<MarkBuffer<&T>> for Mark {
    fn parse(buf: &MarkBuffer<&T>) -> Result<Self, DecodeError> {
        Ok(Mark {
            value: buf.value(),
            mask: buf.mask(),
        })
    }
}

impl Emitable for Mark {
    fn buffer_len(&self) -> usize {
        XFRM_MARK_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = MarkBuffer::new(buffer);
        buffer.set_value(self.value);
        buffer.set_mask(self.mask);
    }
}
