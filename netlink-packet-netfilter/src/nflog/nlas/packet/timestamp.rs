// SPDX-License-Identifier: MIT

use netlink_packet_core::DecodeError;
use netlink_packet_utils::{buffer, nla::Nla, Parseable};

use crate::constants::NFULA_TIMESTAMP;

const TIMESTAMP_LEN: usize = 16;

buffer!(TimeStampBuffer(TIMESTAMP_LEN) {
    sec: (u64, 0..8),
    usec: (u64, 8..16),
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeStamp {
    sec: u64,
    usec: u64,
}

impl Nla for TimeStamp {
    fn value_len(&self) -> usize {
        TIMESTAMP_LEN
    }

    fn kind(&self) -> u16 {
        NFULA_TIMESTAMP
    }

    fn emit_value(&self, buf: &mut [u8]) {
        let mut buf = TimeStampBuffer::new(buf);
        buf.set_sec(self.sec.to_be());
        buf.set_usec(self.usec.to_be())
    }
}

impl<T: AsRef<[u8]>> Parseable<TimeStampBuffer<T>> for TimeStamp {
    fn parse(buf: &TimeStampBuffer<T>) -> Result<Self, DecodeError> {
        Ok(TimeStamp {
            sec: u64::from_be(buf.sec()),
            usec: u64::from_be(buf.usec()),
        })
    }
}
