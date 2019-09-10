use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NeighbourTableConfig {
    pub key_len: u16,
    pub entry_size: u16,
    pub entries: u32,
    pub last_flush: u32,
    pub last_rand: u32,
    pub hash_rand: u32,
    pub hash_mask: u32,
    pub hash_chain_gc: u32,
    pub proxy_qlen: u32,
}

pub const NEIGHBOUR_TABLE_CONFIG_LEN: usize = 32;

buffer!(NeighbourTableConfigBuffer, NEIGHBOUR_TABLE_CONFIG_LEN);
fields!(NeighbourTableConfigBuffer {
    key_len: (u16, 0..2),
    entry_size: (u16, 2..4),
    entries: (u32, 4..8),
    last_flush: (u32, 8..12),
    last_rand: (u32, 12..16),
    hash_rand: (u32, 16..20),
    hash_mask: (u32, 20..24),
    hash_chain_gc: (u32, 24..28),
    proxy_qlen: (u32, 28..32),
});

impl<T: AsRef<[u8]>> Parseable<NeighbourTableConfig> for NeighbourTableConfigBuffer<T> {
    fn parse(&self) -> Result<NeighbourTableConfig, DecodeError> {
        self.check_buffer_length()?;
        Ok(NeighbourTableConfig {
            key_len: self.key_len(),
            entry_size: self.entry_size(),
            entries: self.entries(),
            last_flush: self.last_flush(),
            last_rand: self.last_rand(),
            hash_rand: self.hash_rand(),
            hash_mask: self.hash_mask(),
            hash_chain_gc: self.hash_chain_gc(),
            proxy_qlen: self.proxy_qlen(),
        })
    }
}

impl Emitable for NeighbourTableConfig {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_TABLE_CONFIG_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NeighbourTableConfigBuffer::new(buffer);
        buffer.set_key_len(self.key_len);
        buffer.set_entry_size(self.entry_size);
        buffer.set_entries(self.entries);
        buffer.set_last_flush(self.last_flush);
        buffer.set_last_rand(self.last_rand);
        buffer.set_hash_rand(self.hash_rand);
        buffer.set_hash_mask(self.hash_mask);
        buffer.set_hash_chain_gc(self.hash_chain_gc);
        buffer.set_proxy_qlen(self.proxy_qlen);
    }
}
