use byteorder::{ByteOrder, NativeEndian};

use crate::{
    rtnl::{
        traits::{Emitable, Parseable},
        Field,
    },
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
const ALLOCS: Field = 0..8;
const DESTROYS: Field = 8..16;
const HASH_GROWS: Field = 16..24;
const RES_FAILED: Field = 24..32;
const LOOKUPS: Field = 32..40;
const HITS: Field = 40..48;
const MULTICAST_PROBES_RECEIVED: Field = 48..56;
const UNICAST_PROBES_RECEIVED: Field = 56..64;
const PERIODIC_GC_RUNS: Field = 64..72;
const FORCED_GC_RUNS: Field = 72..80;
pub const NEIGHBOUR_TABLE_STATS_LEN: usize = FORCED_GC_RUNS.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourTableStatsBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NeighbourTableStatsBuffer<T> {
    pub fn new(buffer: T) -> NeighbourTableStatsBuffer<T> {
        NeighbourTableStatsBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<NeighbourTableStatsBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < NEIGHBOUR_TABLE_STATS_LEN {
            return Err(format!(
                "invalid NeighbourTableStatsBuffer buffer: length is {} instead of {}",
                len, NEIGHBOUR_TABLE_STATS_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn allocs(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[ALLOCS])
    }

    pub fn destroys(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[DESTROYS])
    }

    pub fn hash_grows(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[HASH_GROWS])
    }

    pub fn res_failed(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RES_FAILED])
    }

    pub fn lookups(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[LOOKUPS])
    }

    pub fn hits(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[HITS])
    }

    pub fn multicast_probes_received(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[MULTICAST_PROBES_RECEIVED])
    }

    pub fn unicast_probes_received(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[UNICAST_PROBES_RECEIVED])
    }

    pub fn periodic_gc_runs(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[PERIODIC_GC_RUNS])
    }

    pub fn forced_gc_runs(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[FORCED_GC_RUNS])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighbourTableStatsBuffer<T> {
    pub fn set_allocs(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[ALLOCS], value)
    }

    pub fn set_destroys(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[DESTROYS], value)
    }

    pub fn set_hash_grows(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[HASH_GROWS], value)
    }

    pub fn set_res_failed(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RES_FAILED], value)
    }

    pub fn set_lookups(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[LOOKUPS], value)
    }

    pub fn set_hits(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[HITS], value)
    }

    pub fn set_multicast_probes_received(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[MULTICAST_PROBES_RECEIVED], value)
    }

    pub fn set_unicast_probes_received(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[UNICAST_PROBES_RECEIVED], value)
    }

    pub fn set_periodic_gc_runs(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[PERIODIC_GC_RUNS], value)
    }

    pub fn set_forced_gc_runs(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[FORCED_GC_RUNS], value)
    }
}

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
