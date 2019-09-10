use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NeighbourTableStats {
    pub allocs: u64,
    pub destroys: u64,
    pub hash_grows: u64,
    pub res_failed: u64,
    pub lookups: u64,
    pub hits: u64,
    pub multicast_probes_received: u64,
    pub unicast_probes_received: u64,
    pub periodic_gc_runs: u64,
    pub forced_gc_runs: u64,
}

pub const NEIGHBOUR_TABLE_STATS_LEN: usize = 80;
buffer!(NeighbourTableStatsBuffer(NEIGHBOUR_TABLE_STATS_LEN) {
    allocs: (u64, 0..8),
    destroys: (u64, 8..16),
    hash_grows: (u64, 16..24),
    res_failed: (u64, 24..32),
    lookups: (u64, 32..40),
    hits: (u64, 40..48),
    multicast_probes_received: (u64, 48..56),
    unicast_probes_received: (u64, 56..64),
    periodic_gc_runs: (u64, 64..72),
    forced_gc_runs: (u64, 72..80),
});

impl<T: AsRef<[u8]>> Parseable<NeighbourTableStats> for NeighbourTableStatsBuffer<T> {
    fn parse(&self) -> Result<NeighbourTableStats, DecodeError> {
        self.check_buffer_length()?;
        Ok(NeighbourTableStats {
            allocs: self.allocs(),
            destroys: self.destroys(),
            hash_grows: self.hash_grows(),
            res_failed: self.res_failed(),
            lookups: self.lookups(),
            hits: self.hits(),
            multicast_probes_received: self.multicast_probes_received(),
            unicast_probes_received: self.unicast_probes_received(),
            periodic_gc_runs: self.periodic_gc_runs(),
            forced_gc_runs: self.forced_gc_runs(),
        })
    }
}

impl Emitable for NeighbourTableStats {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_TABLE_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NeighbourTableStatsBuffer::new(buffer);
        buffer.set_allocs(self.allocs);
        buffer.set_destroys(self.destroys);
        buffer.set_hash_grows(self.hash_grows);
        buffer.set_res_failed(self.res_failed);
        buffer.set_lookups(self.lookups);
        buffer.set_hits(self.hits);
        buffer.set_multicast_probes_received(self.multicast_probes_received);
        buffer.set_unicast_probes_received(self.unicast_probes_received);
        buffer.set_periodic_gc_runs(self.periodic_gc_runs);
        buffer.set_forced_gc_runs(self.forced_gc_runs);
    }
}
