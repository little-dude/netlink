// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, errors::DecodeError, nla::Nla, Parseable};

const NFULA_CFG_MODE: u16 = libc::NFULA_CFG_MODE as u16;
const NFULNL_COPY_NONE: u8 = libc::NFULNL_COPY_NONE as u8;
const NFULNL_COPY_META: u8 = libc::NFULNL_COPY_META as u8;
const NFULNL_COPY_PACKET: u8 = libc::NFULNL_COPY_PACKET as u8;

const CONFIG_MODE_LEN: usize = 6;

buffer!(ConfigModeBuffer(CONFIG_MODE_LEN) {
    copy_range: (u32, 0..4),
    copy_mode: (u8, 4),
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMode {
    None,
    Meta,
    Packet,
    Other(u8),
}

impl From<CopyMode> for u8 {
    fn from(cmd: CopyMode) -> Self {
        match cmd {
            CopyMode::None => NFULNL_COPY_NONE,
            CopyMode::Meta => NFULNL_COPY_META,
            CopyMode::Packet => NFULNL_COPY_PACKET,
            CopyMode::Other(cmd) => cmd,
        }
    }
}

impl From<u8> for CopyMode {
    fn from(cmd: u8) -> Self {
        match cmd {
            NFULNL_COPY_NONE => CopyMode::None,
            NFULNL_COPY_META => CopyMode::Meta,
            NFULNL_COPY_PACKET => CopyMode::Packet,
            cmd => CopyMode::Other(cmd),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigMode {
    copy_range: u32,
    copy_mode: CopyMode,
}

impl ConfigMode {
    pub const NONE: Self = Self {
        copy_range: 0,
        copy_mode: CopyMode::None,
    };

    pub const META: Self = Self {
        copy_range: 0,
        copy_mode: CopyMode::Meta,
    };

    pub const PACKET_MAX: Self = Self {
        copy_range: 0,
        copy_mode: CopyMode::Packet,
    };

    pub fn new(copy_range: u32, copy_mode: CopyMode) -> Self {
        Self {
            copy_range,
            copy_mode,
        }
    }

    pub fn new_packet(copy_range: u32) -> Self {
        Self::new(copy_range, CopyMode::Packet)
    }
}

impl Nla for ConfigMode {
    fn value_len(&self) -> usize {
        CONFIG_MODE_LEN
    }

    fn kind(&self) -> u16 {
        NFULA_CFG_MODE
    }

    fn emit_value(&self, buf: &mut [u8]) {
        let mut buf = ConfigModeBuffer::new(buf);
        buf.set_copy_range(self.copy_range.to_be());
        buf.set_copy_mode(self.copy_mode.into())
    }
}

impl<T: AsRef<[u8]>> Parseable<ConfigModeBuffer<T>> for ConfigMode {
    fn parse(buf: &ConfigModeBuffer<T>) -> Result<Self, DecodeError> {
        Ok(ConfigMode {
            copy_range: u32::from_be(buf.copy_range()),
            copy_mode: buf.copy_mode().into(),
        })
    }
}
