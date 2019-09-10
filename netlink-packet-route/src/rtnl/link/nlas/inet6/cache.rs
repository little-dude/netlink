use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInet6CacheInfo {
    pub max_reasm_len: i32,
    pub tstamp: i32,
    pub reachable_time: i32,
    pub retrans_time: i32,
}

pub const LINK_INET6_CACHE_INFO_LEN: usize = 16;
buffer!(LinkInet6CacheInfoBuffer, LINK_INET6_CACHE_INFO_LEN);
fields!(LinkInet6CacheInfoBuffer {
    max_reasm_len: (i32, 0..4),
    tstamp: (i32, 4..8),
    reachable_time: (i32, 8..12),
    retrans_time: (i32, 12..16),
});

impl<T: AsRef<[u8]>> Parseable<LinkInet6CacheInfo> for LinkInet6CacheInfoBuffer<T> {
    fn parse(&self) -> Result<LinkInet6CacheInfo, DecodeError> {
        Ok(LinkInet6CacheInfo {
            max_reasm_len: self.max_reasm_len(),
            tstamp: self.tstamp(),
            reachable_time: self.reachable_time(),
            retrans_time: self.retrans_time(),
        })
    }
}

impl Emitable for LinkInet6CacheInfo {
    fn buffer_len(&self) -> usize {
        LINK_INET6_CACHE_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkInet6CacheInfoBuffer::new(buffer);
        buffer.set_max_reasm_len(self.max_reasm_len);
        buffer.set_tstamp(self.tstamp);
        buffer.set_reachable_time(self.reachable_time);
        buffer.set_retrans_time(self.retrans_time);
    }
}
