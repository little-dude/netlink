// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address,
    AddressBuffer,
    XFRM_ADDRESS_LEN,
};

use netlink_packet_utils::{
    buffer,
    traits::*,
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Selector {
    pub daddr: Address,
    pub saddr: Address,
    pub dport: u16,      // big-endian
    pub dport_mask: u16, // big-endian
    pub sport: u16,      // big-endian
    pub sport_mask: u16, // big-endian
    pub family: u16,
    pub prefixlen_d: u8,
    pub prefixlen_s: u8,
    pub proto: u8,
    pub ifindex: i32, // "int" in iproute2
    pub user: u32     // "__kernel_uid32_t" in iproute2
}

const DADDR_FIELD: Range<usize>      = 0..XFRM_ADDRESS_LEN;
const SADDR_FIELD: Range<usize>      = DADDR_FIELD.end..(DADDR_FIELD.end + XFRM_ADDRESS_LEN);
const DPORT_FIELD: Range<usize>      = SADDR_FIELD.end..(SADDR_FIELD.end + 2);
const DPORT_MASK_FIELD: Range<usize> = DPORT_FIELD.end..(DPORT_FIELD.end + 2);
const SPORT_FIELD: Range<usize>      = DPORT_MASK_FIELD.end..(DPORT_MASK_FIELD.end + 2);
const SPORT_MASK_FIELD: Range<usize> = SPORT_FIELD.end..(SPORT_FIELD.end + 2);
const FAMILY_FIELD: Range<usize>     = SPORT_MASK_FIELD.end..(SPORT_MASK_FIELD.end + 2);
const PREFIXLEN_D_FIELD: usize       = FAMILY_FIELD.end;
const PREFIXLEN_S_FIELD: usize       = PREFIXLEN_D_FIELD + 1;
const PROTO_FIELD: usize             = PREFIXLEN_S_FIELD + 1;
const IFINDEX_FIELD: Range<usize>    = (PROTO_FIELD + 4)..(PROTO_FIELD + 4 + 4);
const USER_FIELD: Range<usize>       = IFINDEX_FIELD.end..(IFINDEX_FIELD.end + 4);

pub const XFRM_SELECTOR_LEN: usize = USER_FIELD.end; //56

buffer!(SelectorBuffer(XFRM_SELECTOR_LEN) {
    daddr: (slice, DADDR_FIELD),
    saddr: (slice, SADDR_FIELD),
    dport: (u16, DPORT_FIELD),
    dport_mask: (u16, DPORT_MASK_FIELD),
    sport: (u16, SPORT_FIELD),
    sport_mask: (u16, SPORT_MASK_FIELD),
    family: (u16, FAMILY_FIELD),
    prefixlen_d: (u8, PREFIXLEN_D_FIELD),
    prefixlen_s: (u8, PREFIXLEN_S_FIELD),
    proto: (u8, PROTO_FIELD),
    /* 3 bytes of padding at (45..48) between proto and ifindex */
    ifindex: (i32, IFINDEX_FIELD),
    user: (u32, USER_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<SelectorBuffer<&T>> for Selector {
    fn parse(buf: &SelectorBuffer<&T>) -> Result<Self, DecodeError> {
        let daddr = Address::parse(&AddressBuffer::new(&buf.daddr()))
            .context("failed to parse daddr")?;
        let saddr = Address::parse(&AddressBuffer::new(&buf.saddr()))
            .context("failed to parse saddr")?;
        Ok(Selector {
            daddr,
            saddr,
            dport: u16::from_be(buf.dport()),
            dport_mask: u16::from_be(buf.dport_mask()),
            sport: u16::from_be(buf.sport()),
            sport_mask: u16::from_be(buf.sport_mask()),
            family: buf.family(),
            prefixlen_d: buf.prefixlen_d(),
            prefixlen_s: buf.prefixlen_s(),
            proto: buf.proto(),
            ifindex: buf.ifindex(),
            user: buf.user()
        })
    }
}

impl Emitable for Selector {
    fn buffer_len(&self) -> usize {
        XFRM_SELECTOR_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = SelectorBuffer::new(buffer);
        self.daddr.emit(buffer.daddr_mut());
        self.saddr.emit(buffer.saddr_mut());
        buffer.set_dport(self.dport.to_be());
        buffer.set_dport_mask(self.dport_mask.to_be());
        buffer.set_sport(self.sport.to_be());
        buffer.set_sport_mask(self.sport_mask.to_be());
        buffer.set_family(self.family);
        buffer.set_prefixlen_d(self.prefixlen_d);
        buffer.set_prefixlen_s(self.prefixlen_s);
        buffer.set_proto(self.proto);
        buffer.set_ifindex(self.ifindex);
        buffer.set_user(self.user);
    }
}
