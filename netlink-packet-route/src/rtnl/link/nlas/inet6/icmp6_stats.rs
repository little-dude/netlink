use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkIcmp6Stats {
    pub num: i64,
    pub in_msgs: i64,
    pub in_errors: i64,
    pub out_msgs: i64,
    pub out_errors: i64,
    pub csum_errors: i64,
}

pub const LINK_ICMP6_STATS_LEN: usize = 48;
buffer!(LinkIcmp6StatsBuffer(LINK_ICMP6_STATS_LEN) {
    num: (i64, 0..8),
    in_msgs: (i64, 8..16),
    in_errors: (i64, 16..24),
    out_msgs: (i64, 24..32),
    out_errors: (i64, 32..40),
    csum_errors: (i64, 40..48),
});

impl<T: AsRef<[u8]>> Parseable<LinkIcmp6Stats> for LinkIcmp6StatsBuffer<T> {
    fn parse(&self) -> Result<LinkIcmp6Stats, DecodeError> {
        Ok(LinkIcmp6Stats {
            num: self.num(),
            in_msgs: self.in_msgs(),
            in_errors: self.in_errors(),
            out_msgs: self.out_msgs(),
            out_errors: self.out_errors(),
            csum_errors: self.csum_errors(),
        })
    }
}

impl Emitable for LinkIcmp6Stats {
    fn buffer_len(&self) -> usize {
        LINK_ICMP6_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkIcmp6StatsBuffer::new(buffer);
        buffer.set_num(self.num);
        buffer.set_in_msgs(self.in_msgs);
        buffer.set_in_errors(self.in_errors);
        buffer.set_out_msgs(self.out_msgs);
        buffer.set_out_errors(self.out_errors);
        buffer.set_csum_errors(self.csum_errors);
    }
}
