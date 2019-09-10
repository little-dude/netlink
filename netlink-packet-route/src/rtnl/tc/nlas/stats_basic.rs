use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

/// Byte/Packet throughput statistics
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcStatsBasic {
    /// number of seen bytes
    pub bytes: u64,
    /// number of seen packets
    pub packets: u32,
}

pub const TC_STATS_BASIC_LEN: usize = 12;

buffer!(TcStatsBasicBuffer, 12);
fields!(TcStatsBasicBuffer {
    bytes: (u64, 0..8),
    packets: (u32, 8..12),
});

impl<T: AsRef<[u8]>> Parseable<TcStatsBasic> for TcStatsBasicBuffer<T> {
    fn parse(&self) -> Result<TcStatsBasic, DecodeError> {
        self.check_buffer_length()?;
        Ok(TcStatsBasic {
            bytes: self.bytes(),
            packets: self.packets(),
        })
    }
}

impl Emitable for TcStatsBasic {
    fn buffer_len(&self) -> usize {
        TC_STATS_BASIC_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TcStatsBasicBuffer::new(buffer);
        buffer.set_bytes(self.bytes);
        buffer.set_packets(self.packets);
    }
}
