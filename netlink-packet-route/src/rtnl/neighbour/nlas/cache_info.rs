use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NeighbourCacheInfo {
    pub confirmed: u32,
    pub used: u32,
    pub updated: u32,
    pub refcnt: u32,
}

pub const NEIGHBOUR_CACHE_INFO_LEN: usize = 16;

buffer!(NeighbourCacheInfoBuffer, NEIGHBOUR_CACHE_INFO_LEN);
fields!(NeighbourCacheInfoBuffer {
    confirmed: (u32, 0..4),
    used: (u32, 4..8),
    updated: (u32, 8..12),
    refcnt: (u32, 12..16),
});

impl<T: AsRef<[u8]>> Parseable<NeighbourCacheInfo> for NeighbourCacheInfoBuffer<T> {
    fn parse(&self) -> Result<NeighbourCacheInfo, DecodeError> {
        self.check_buffer_length()?;
        Ok(NeighbourCacheInfo {
            confirmed: self.confirmed(),
            used: self.used(),
            updated: self.updated(),
            refcnt: self.refcnt(),
        })
    }
}

impl Emitable for NeighbourCacheInfo {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_CACHE_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NeighbourCacheInfoBuffer::new(buffer);
        buffer.set_confirmed(self.confirmed);
        buffer.set_used(self.used);
        buffer.set_updated(self.updated);
        buffer.set_refcnt(self.refcnt);
    }
}
