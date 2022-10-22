// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SpdInfo {
    pub incnt: u32,
    pub outcnt: u32,
    pub fwdcnt: u32,
    pub inscnt: u32,
    pub outscnt: u32,
    pub fwdscnt: u32,
}

pub const XFRM_SPD_INFO_LEN: usize = 24;

buffer!(SpdInfoBuffer(XFRM_SPD_INFO_LEN) {
    incnt: (u32, 0..4),
    outcnt: (u32, 4..8),
    fwdcnt: (u32, 8..12),
    inscnt: (u32, 12..16),
    outscnt: (u32, 16..20),
    fwdscnt: (u32, 20..24),
});

impl<T: AsRef<[u8]>> Parseable<SpdInfoBuffer<T>> for SpdInfo {
    fn parse(buf: &SpdInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(SpdInfo {
            incnt: buf.incnt(),
            outcnt: buf.outcnt(),
            fwdcnt: buf.fwdcnt(),
            inscnt: buf.inscnt(),
            outscnt: buf.outscnt(),
            fwdscnt: buf.fwdscnt(),
        })
    }
}

impl Emitable for SpdInfo {
    fn buffer_len(&self) -> usize {
        XFRM_SPD_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = SpdInfoBuffer::new(buffer);
        buffer.set_incnt(self.incnt);
        buffer.set_outcnt(self.outcnt);
        buffer.set_fwdcnt(self.fwdcnt);
        buffer.set_inscnt(self.inscnt);
        buffer.set_outscnt(self.outscnt);
        buffer.set_fwdscnt(self.fwdscnt);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SpdHInfo {
    pub spdhcnt: u32,
    pub spdhmcnt: u32,
}

pub const XFRM_SPD_HINFO_LEN: usize = 8;

buffer!(SpdHInfoBuffer(XFRM_SPD_HINFO_LEN) {
    spdhcnt: (u32, 0..4),
    spdhmcnt: (u32, 4..8)
});

impl<T: AsRef<[u8]>> Parseable<SpdHInfoBuffer<T>> for SpdHInfo {
    fn parse(buf: &SpdHInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(SpdHInfo {
            spdhcnt: buf.spdhcnt(),
            spdhmcnt: buf.spdhmcnt(),
        })
    }
}

impl Emitable for SpdHInfo {
    fn buffer_len(&self) -> usize {
        XFRM_SPD_HINFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = SpdHInfoBuffer::new(buffer);
        buffer.set_spdhcnt(self.spdhcnt);
        buffer.set_spdhmcnt(self.spdhmcnt);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SpdHThresh {
    pub lbits: u8,
    pub rbits: u8,
}

pub const XFRM_SPD_HTHRESH_LEN: usize = 2;

buffer!(SpdHThreshBuffer(XFRM_SPD_HTHRESH_LEN) {
    lbits: (u8, 0),
    rbits: (u8, 1)
});

impl<T: AsRef<[u8]>> Parseable<SpdHThreshBuffer<T>> for SpdHThresh {
    fn parse(buf: &SpdHThreshBuffer<T>) -> Result<Self, DecodeError> {
        Ok(SpdHThresh {
            lbits: buf.lbits(),
            rbits: buf.rbits(),
        })
    }
}

impl Emitable for SpdHThresh {
    fn buffer_len(&self) -> usize {
        XFRM_SPD_HTHRESH_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = SpdHThreshBuffer::new(buffer);
        buffer.set_lbits(self.lbits);
        buffer.set_rbits(self.rbits);
    }
}
