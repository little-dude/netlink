use std::mem::size_of;

use bitflags::bitflags;
use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::nla::Nla;

const NFULA_CFG_FLAGS: u16 = libc::NFULA_CFG_FLAGS as u16;

bitflags! {
    pub struct ConfigFlags: u16 {
        const SEQ = libc:: NFULNL_CFG_F_SEQ as u16;
        const SEQ_GLOBAL = libc:: NFULNL_CFG_F_SEQ_GLOBAL as u16;
        const CONNTRACK = libc:: NFULNL_CFG_F_CONNTRACK as u16;
    }
}

impl Nla for ConfigFlags {
    fn value_len(&self) -> usize {
        size_of::<Self>()
    }

    fn kind(&self) -> u16 {
        NFULA_CFG_FLAGS
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        BigEndian::write_u16(buffer, self.bits);
    }
}
