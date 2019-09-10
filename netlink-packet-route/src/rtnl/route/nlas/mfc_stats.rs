use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RouteMfcStats {
    pub packets: u64,
    pub bytes: u64,
    pub wrong_if: u64,
}

pub const ROUTE_MFC_STATS_LEN: usize = 24;

buffer!(RouteMfcStatsBuffer, ROUTE_MFC_STATS_LEN);
fields!(RouteMfcStatsBuffer {
    packets: (u64, 0..8),
    bytes: (u64, 8..16),
    wrong_if: (u64, 16..24),
});

impl<T: AsRef<[u8]>> Parseable<RouteMfcStats> for RouteMfcStatsBuffer<T> {
    fn parse(&self) -> Result<RouteMfcStats, DecodeError> {
        Ok(RouteMfcStats {
            packets: self.packets(),
            bytes: self.bytes(),
            wrong_if: self.wrong_if(),
        })
    }
}

impl Emitable for RouteMfcStats {
    fn buffer_len(&self) -> usize {
        ROUTE_MFC_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = RouteMfcStatsBuffer::new(buffer);
        buffer.set_packets(self.packets);
        buffer.set_bytes(self.bytes);
        buffer.set_wrong_if(self.wrong_if);
    }
}
