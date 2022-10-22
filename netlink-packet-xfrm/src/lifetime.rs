// SPDX-License-Identifier: MIT

use crate::XFRM_INF;

use netlink_packet_utils::{buffer, traits::*, DecodeError};

// Lifetime config

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LifetimeConfig {
    pub soft_byte_limit: u64,
    pub hard_byte_limit: u64,
    pub soft_packet_limit: u64,
    pub hard_packet_limit: u64,
    pub soft_add_expires_seconds: u64,
    pub hard_add_expires_seconds: u64,
    pub soft_use_expires_seconds: u64,
    pub hard_use_expires_seconds: u64,
}

pub const XFRM_LIFETIME_CONFIG_LEN: usize = 64;

buffer!(LifetimeConfigBuffer(XFRM_LIFETIME_CONFIG_LEN) {
    soft_byte_limit: (u64, 0..8),
    hard_byte_limit: (u64, 8..16),
    soft_packet_limit: (u64, 16..24),
    hard_packet_limit: (u64, 24..32),
    soft_add_expires_seconds: (u64, 32..40),
    hard_add_expires_seconds: (u64, 40..48),
    soft_use_expires_seconds: (u64, 48..56),
    hard_use_expires_seconds: (u64, 56..64)
});

impl Default for LifetimeConfig {
    fn default() -> Self {
        LifetimeConfig {
            soft_byte_limit: XFRM_INF,
            hard_byte_limit: XFRM_INF,
            soft_packet_limit: XFRM_INF,
            hard_packet_limit: XFRM_INF,
            soft_add_expires_seconds: 0,
            hard_add_expires_seconds: 0,
            soft_use_expires_seconds: 0,
            hard_use_expires_seconds: 0,
        }
    }
}

impl<T: AsRef<[u8]>> Parseable<LifetimeConfigBuffer<T>> for LifetimeConfig {
    fn parse(buf: &LifetimeConfigBuffer<T>) -> Result<Self, DecodeError> {
        Ok(LifetimeConfig {
            soft_byte_limit: buf.soft_byte_limit(),
            hard_byte_limit: buf.hard_byte_limit(),
            soft_packet_limit: buf.soft_packet_limit(),
            hard_packet_limit: buf.hard_packet_limit(),
            soft_add_expires_seconds: buf.soft_add_expires_seconds(),
            hard_add_expires_seconds: buf.hard_add_expires_seconds(),
            soft_use_expires_seconds: buf.soft_use_expires_seconds(),
            hard_use_expires_seconds: buf.hard_use_expires_seconds(),
        })
    }
}

impl Emitable for LifetimeConfig {
    fn buffer_len(&self) -> usize {
        XFRM_LIFETIME_CONFIG_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LifetimeConfigBuffer::new(buffer);
        buffer.set_soft_byte_limit(self.soft_byte_limit);
        buffer.set_hard_byte_limit(self.hard_byte_limit);
        buffer.set_soft_packet_limit(self.soft_packet_limit);
        buffer.set_hard_packet_limit(self.hard_packet_limit);
        buffer.set_soft_add_expires_seconds(self.soft_add_expires_seconds);
        buffer.set_hard_add_expires_seconds(self.hard_add_expires_seconds);
        buffer.set_soft_use_expires_seconds(self.soft_use_expires_seconds);
        buffer.set_hard_use_expires_seconds(self.hard_use_expires_seconds);
    }
}

// Lifetime curent

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Lifetime {
    pub bytes: u64,
    pub packets: u64,
    pub add_time: u64,
    pub use_time: u64,
}

pub const XFRM_LIFETIME_LEN: usize = 32;

buffer!(LifetimeBuffer(XFRM_LIFETIME_LEN) {
    bytes: (u64, 0..8),
    packets: (u64, 8..16),
    add_time: (u64, 16..24),
    use_time: (u64, 24..32)
});

impl<T: AsRef<[u8]>> Parseable<LifetimeBuffer<T>> for Lifetime {
    fn parse(buf: &LifetimeBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Lifetime {
            bytes: buf.bytes(),
            packets: buf.packets(),
            add_time: buf.add_time(),
            use_time: buf.use_time(),
        })
    }
}

impl Emitable for Lifetime {
    fn buffer_len(&self) -> usize {
        XFRM_LIFETIME_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LifetimeBuffer::new(buffer);
        buffer.set_bytes(self.bytes);
        buffer.set_packets(self.packets);
        buffer.set_add_time(self.add_time);
        buffer.set_use_time(self.use_time);
    }
}
