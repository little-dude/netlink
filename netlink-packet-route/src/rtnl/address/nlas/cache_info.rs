use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AddressCacheInfo {
    pub ifa_preferred: i32,
    pub ifa_valid: i32,
    pub cstamp: i32,
    pub tstamp: i32,
}

pub const ADDRESSS_CACHE_INFO_LEN: usize = 16;
buffer!(AddressCacheInfoBuffer, ADDRESSS_CACHE_INFO_LEN);
fields!(AddressCacheInfoBuffer {
    ifa_preferred: (i32, 0..4),
    ifa_valid: (i32, 4..8),
    cstamp: (i32, 8..12),
    tstamp: (i32, 12..16),
});

impl<T: AsRef<[u8]>> Parseable<AddressCacheInfo> for AddressCacheInfoBuffer<T> {
    fn parse(&self) -> Result<AddressCacheInfo, DecodeError> {
        Ok(AddressCacheInfo {
            ifa_preferred: self.ifa_preferred(),
            ifa_valid: self.ifa_valid(),
            cstamp: self.cstamp(),
            tstamp: self.tstamp(),
        })
    }
}

impl Emitable for AddressCacheInfo {
    fn buffer_len(&self) -> usize {
        ADDRESSS_CACHE_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = AddressCacheInfoBuffer::new(buffer);
        buffer.set_ifa_preferred(self.ifa_preferred);
        buffer.set_ifa_valid(self.ifa_valid);
        buffer.set_cstamp(self.cstamp);
        buffer.set_tstamp(self.tstamp);
    }
}
