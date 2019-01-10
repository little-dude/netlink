use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

const NUM: Field = 0..8;
const IN_PKTS: Field = 8..16;
const IN_OCTETS: Field = 16..24;
const IN_DELIVERS: Field = 24..32;
const OUT_FORW_DATAGRAMS: Field = 32..40;
const OUT_PKTS: Field = 40..48;
const OUT_OCTETS: Field = 48..56;
const IN_HDR_ERRORS: Field = 56..64;
const IN_TOO_BIG_ERRORS: Field = 64..72;
const IN_NO_ROUTES: Field = 72..80;
const IN_ADDR_ERRORS: Field = 80..88;
const IN_UNKNOWN_PROTOS: Field = 88..96;
const IN_TRUNCATED_PKTS: Field = 96..104;
const IN_DISCARDS: Field = 104..112;
const OUT_DISCARDS: Field = 112..120;
const OUT_NO_ROUTES: Field = 120..128;
const REASM_TIMEOUT: Field = 128..136;
const REASM_REQDS: Field = 136..144;
const REASM_OKS: Field = 144..152;
const REASM_FAILS: Field = 152..160;
const FRAG_OKS: Field = 160..168;
const FRAG_FAILS: Field = 168..176;
const FRAG_CREATES: Field = 176..184;
const IN_MCAST_PKTS: Field = 184..192;
const OUT_MCAST_PKTS: Field = 192..200;
const IN_BCAST_PKTS: Field = 200..208;
const OUT_BCAST_PKTS: Field = 208..216;
const IN_MCAST_OCTETS: Field = 216..224;
const OUT_MCAST_OCTETS: Field = 224..232;
const IN_BCAST_OCTETS: Field = 232..240;
const OUT_BCAST_OCTETS: Field = 240..248;
const IN_CSUM_ERRORS: Field = 248..256;
const IN_NO_ECT_PKTS: Field = 256..264;
const IN_ECT1_PKTS: Field = 264..272;
const IN_ECT0_PKTS: Field = 272..280;
const IN_CE_PKTS: Field = 280..288;

pub const LINK_INET6_STATS_LEN: usize = IN_CE_PKTS.end;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct LinkInet6Stats {
    pub num: i64,
    pub in_pkts: i64,
    pub in_octets: i64,
    pub in_delivers: i64,
    pub out_forw_datagrams: i64,
    pub out_pkts: i64,
    pub out_octets: i64,
    pub in_hdr_errors: i64,
    pub in_too_big_errors: i64,
    pub in_no_routes: i64,
    pub in_addr_errors: i64,
    pub in_unknown_protos: i64,
    pub in_truncated_pkts: i64,
    pub in_discards: i64,
    pub out_discards: i64,
    pub out_no_routes: i64,
    pub reasm_timeout: i64,
    pub reasm_reqds: i64,
    pub reasm_oks: i64,
    pub reasm_fails: i64,
    pub frag_oks: i64,
    pub frag_fails: i64,
    pub frag_creates: i64,
    pub in_mcast_pkts: i64,
    pub out_mcast_pkts: i64,
    pub in_bcast_pkts: i64,
    pub out_bcast_pkts: i64,
    pub in_mcast_octets: i64,
    pub out_mcast_octets: i64,
    pub in_bcast_octets: i64,
    pub out_bcast_octets: i64,
    pub in_csum_errors: i64,
    pub in_no_ect_pkts: i64,
    pub in_ect1_pkts: i64,
    pub in_ect0_pkts: i64,
    pub in_ce_pkts: i64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkInet6StatsBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkInet6StatsBuffer<T> {
    pub fn new(buffer: T) -> Self {
        LinkInet6StatsBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_INET6_STATS_LEN {
            return Err(format!(
                "invalid LinkInet6StatsBuffer buffer: length is {} instead of {}",
                len, LINK_INET6_STATS_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn num(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[NUM])
    }

    pub fn in_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_PKTS])
    }

    pub fn in_octets(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_OCTETS])
    }

    pub fn in_delivers(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_DELIVERS])
    }

    pub fn out_forw_datagrams(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_FORW_DATAGRAMS])
    }

    pub fn out_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_PKTS])
    }

    pub fn out_octets(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_OCTETS])
    }

    pub fn in_hdr_errors(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_HDR_ERRORS])
    }

    pub fn in_too_big_errors(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_TOO_BIG_ERRORS])
    }

    pub fn in_no_routes(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_NO_ROUTES])
    }

    pub fn in_addr_errors(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_ADDR_ERRORS])
    }

    pub fn in_unknown_protos(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_UNKNOWN_PROTOS])
    }

    pub fn in_truncated_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_TRUNCATED_PKTS])
    }

    pub fn in_discards(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_DISCARDS])
    }

    pub fn out_discards(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_DISCARDS])
    }

    pub fn out_no_routes(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_NO_ROUTES])
    }

    pub fn reasm_timeout(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[REASM_TIMEOUT])
    }

    pub fn reasm_reqds(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[REASM_REQDS])
    }

    pub fn reasm_oks(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[REASM_OKS])
    }

    pub fn reasm_fails(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[REASM_FAILS])
    }

    pub fn frag_oks(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[FRAG_OKS])
    }

    pub fn frag_fails(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[FRAG_FAILS])
    }

    pub fn frag_creates(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[FRAG_CREATES])
    }

    pub fn in_mcast_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_MCAST_PKTS])
    }

    pub fn out_mcast_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_MCAST_PKTS])
    }

    pub fn in_bcast_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_BCAST_PKTS])
    }

    pub fn out_bcast_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_BCAST_PKTS])
    }

    pub fn in_mcast_octets(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_MCAST_OCTETS])
    }

    pub fn out_mcast_octets(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_MCAST_OCTETS])
    }

    pub fn in_bcast_octets(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_BCAST_OCTETS])
    }

    pub fn out_bcast_octets(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[OUT_BCAST_OCTETS])
    }

    pub fn in_csum_errors(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_CSUM_ERRORS])
    }

    pub fn in_no_ect_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_NO_ECT_PKTS])
    }

    pub fn in_ect1_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_ECT1_PKTS])
    }

    pub fn in_ect0_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_ECT0_PKTS])
    }

    pub fn in_ce_pkts(&self) -> i64 {
        NativeEndian::read_i64(&self.buffer.as_ref()[IN_CE_PKTS])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkInet6StatsBuffer<T> {
    pub fn set_num(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[NUM], value)
    }
    pub fn set_in_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_PKTS], value)
    }
    pub fn set_in_octets(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_OCTETS], value)
    }
    pub fn set_in_delivers(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_DELIVERS], value)
    }
    pub fn set_out_forw_datagrams(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_FORW_DATAGRAMS], value)
    }
    pub fn set_out_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_PKTS], value)
    }
    pub fn set_out_octets(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_OCTETS], value)
    }
    pub fn set_in_hdr_errors(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_HDR_ERRORS], value)
    }
    pub fn set_in_too_big_errors(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_TOO_BIG_ERRORS], value)
    }
    pub fn set_in_no_routes(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_NO_ROUTES], value)
    }
    pub fn set_in_addr_errors(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_ADDR_ERRORS], value)
    }
    pub fn set_in_unknown_protos(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_UNKNOWN_PROTOS], value)
    }
    pub fn set_in_truncated_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_TRUNCATED_PKTS], value)
    }
    pub fn set_in_discards(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_DISCARDS], value)
    }
    pub fn set_out_discards(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_DISCARDS], value)
    }
    pub fn set_out_no_routes(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_NO_ROUTES], value)
    }
    pub fn set_reasm_timeout(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[REASM_TIMEOUT], value)
    }
    pub fn set_reasm_reqds(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[REASM_REQDS], value)
    }
    pub fn set_reasm_oks(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[REASM_OKS], value)
    }
    pub fn set_reasm_fails(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[REASM_FAILS], value)
    }
    pub fn set_frag_oks(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[FRAG_OKS], value)
    }
    pub fn set_frag_fails(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[FRAG_FAILS], value)
    }
    pub fn set_frag_creates(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[FRAG_CREATES], value)
    }
    pub fn set_in_mcast_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_MCAST_PKTS], value)
    }
    pub fn set_out_mcast_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_MCAST_PKTS], value)
    }
    pub fn set_in_bcast_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_BCAST_PKTS], value)
    }
    pub fn set_out_bcast_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_BCAST_PKTS], value)
    }
    pub fn set_in_mcast_octets(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_MCAST_OCTETS], value)
    }
    pub fn set_out_mcast_octets(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_MCAST_OCTETS], value)
    }
    pub fn set_in_bcast_octets(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_BCAST_OCTETS], value)
    }
    pub fn set_out_bcast_octets(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[OUT_BCAST_OCTETS], value)
    }
    pub fn set_in_csum_errors(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_CSUM_ERRORS], value)
    }
    pub fn set_in_no_ect_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_NO_ECT_PKTS], value)
    }
    pub fn set_in_ect1_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_ECT1_PKTS], value)
    }
    pub fn set_in_ect0_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_ECT0_PKTS], value)
    }
    pub fn set_in_ce_pkts(&mut self, value: i64) {
        NativeEndian::write_i64(&mut self.buffer.as_mut()[IN_CE_PKTS], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkInet6Stats> for LinkInet6StatsBuffer<T> {
    fn parse(&self) -> Result<LinkInet6Stats, DecodeError> {
        self.check_buffer_length()?;
        Ok(LinkInet6Stats {
            num: self.num(),
            in_pkts: self.in_pkts(),
            in_octets: self.in_octets(),
            in_delivers: self.in_delivers(),
            out_forw_datagrams: self.out_forw_datagrams(),
            out_pkts: self.out_pkts(),
            out_octets: self.out_octets(),
            in_hdr_errors: self.in_hdr_errors(),
            in_too_big_errors: self.in_too_big_errors(),
            in_no_routes: self.in_no_routes(),
            in_addr_errors: self.in_addr_errors(),
            in_unknown_protos: self.in_unknown_protos(),
            in_truncated_pkts: self.in_truncated_pkts(),
            in_discards: self.in_discards(),
            out_discards: self.out_discards(),
            out_no_routes: self.out_no_routes(),
            reasm_timeout: self.reasm_timeout(),
            reasm_reqds: self.reasm_reqds(),
            reasm_oks: self.reasm_oks(),
            reasm_fails: self.reasm_fails(),
            frag_oks: self.frag_oks(),
            frag_fails: self.frag_fails(),
            frag_creates: self.frag_creates(),
            in_mcast_pkts: self.in_mcast_pkts(),
            out_mcast_pkts: self.out_mcast_pkts(),
            in_bcast_pkts: self.in_bcast_pkts(),
            out_bcast_pkts: self.out_bcast_pkts(),
            in_mcast_octets: self.in_mcast_octets(),
            out_mcast_octets: self.out_mcast_octets(),
            in_bcast_octets: self.in_bcast_octets(),
            out_bcast_octets: self.out_bcast_octets(),
            in_csum_errors: self.in_csum_errors(),
            in_no_ect_pkts: self.in_no_ect_pkts(),
            in_ect1_pkts: self.in_ect1_pkts(),
            in_ect0_pkts: self.in_ect0_pkts(),
            in_ce_pkts: self.in_ce_pkts(),
        })
    }
}

impl Emitable for LinkInet6Stats {
    fn buffer_len(&self) -> usize {
        LINK_INET6_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkInet6StatsBuffer::new(buffer);
        buffer.set_num(self.num);
        buffer.set_in_pkts(self.in_pkts);
        buffer.set_in_octets(self.in_octets);
        buffer.set_in_delivers(self.in_delivers);
        buffer.set_out_forw_datagrams(self.out_forw_datagrams);
        buffer.set_out_pkts(self.out_pkts);
        buffer.set_out_octets(self.out_octets);
        buffer.set_in_hdr_errors(self.in_hdr_errors);
        buffer.set_in_too_big_errors(self.in_too_big_errors);
        buffer.set_in_no_routes(self.in_no_routes);
        buffer.set_in_addr_errors(self.in_addr_errors);
        buffer.set_in_unknown_protos(self.in_unknown_protos);
        buffer.set_in_truncated_pkts(self.in_truncated_pkts);
        buffer.set_in_discards(self.in_discards);
        buffer.set_out_discards(self.out_discards);
        buffer.set_out_no_routes(self.out_no_routes);
        buffer.set_reasm_timeout(self.reasm_timeout);
        buffer.set_reasm_reqds(self.reasm_reqds);
        buffer.set_reasm_oks(self.reasm_oks);
        buffer.set_reasm_fails(self.reasm_fails);
        buffer.set_frag_oks(self.frag_oks);
        buffer.set_frag_fails(self.frag_fails);
        buffer.set_frag_creates(self.frag_creates);
        buffer.set_in_mcast_pkts(self.in_mcast_pkts);
        buffer.set_out_mcast_pkts(self.out_mcast_pkts);
        buffer.set_in_bcast_pkts(self.in_bcast_pkts);
        buffer.set_out_bcast_pkts(self.out_bcast_pkts);
        buffer.set_in_mcast_octets(self.in_mcast_octets);
        buffer.set_out_mcast_octets(self.out_mcast_octets);
        buffer.set_in_bcast_octets(self.in_bcast_octets);
        buffer.set_out_bcast_octets(self.out_bcast_octets);
        buffer.set_in_csum_errors(self.in_csum_errors);
        buffer.set_in_no_ect_pkts(self.in_no_ect_pkts);
        buffer.set_in_ect1_pkts(self.in_ect1_pkts);
        buffer.set_in_ect0_pkts(self.in_ect0_pkts);
        buffer.set_in_ce_pkts(self.in_ce_pkts);
    }
}
