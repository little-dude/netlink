// SPDX-License-Identifier: MIT

use std::{convert::TryInto, mem::size_of, time::Duration};

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::nla::Nla;

const NFULA_CFG_TIMEOUT: u16 = libc::NFULA_CFG_TIMEOUT as u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeout {
    hundredth: u32,
}

impl Timeout {
    pub fn new(hundredth: u32) -> Self {
        Self { hundredth }
    }
}

impl From<Duration> for Timeout {
    fn from(duration: Duration) -> Self {
        let hundredth = (duration.as_millis() / 10).try_into().unwrap_or(u32::MAX);
        Self { hundredth }
    }
}

impl Nla for Timeout {
    fn value_len(&self) -> usize {
        size_of::<u32>()
    }

    fn kind(&self) -> u16 {
        NFULA_CFG_TIMEOUT
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        BigEndian::write_u32(buffer, self.hundredth);
    }
}
