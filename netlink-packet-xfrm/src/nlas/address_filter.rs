// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address,
    AddressBuffer,
    address::XFRM_ADDRESS_LEN,
};

use netlink_packet_utils::{
    buffer,
    traits::*,
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AddressFilter {
    pub saddr: Address,
    pub daddr: Address,
    pub family: u16,
    pub splen: u8,
    pub dplen: u8
}

const SADDR_FIELD: Range<usize>  = 0..XFRM_ADDRESS_LEN;
const DADDR_FIELD: Range<usize>  = SADDR_FIELD.end..(SADDR_FIELD.end + XFRM_ADDRESS_LEN);
const FAMILY_FIELD: Range<usize> = DADDR_FIELD.end..(DADDR_FIELD.end + 2);
const SPLEN_FIELD: usize         = FAMILY_FIELD.end;
const DPLEN_FIELD: usize         = SPLEN_FIELD + 1;

pub const XFRM_ADDRESS_FILTER_LEN: usize = 36;

buffer!(AddressFilterBuffer(XFRM_ADDRESS_FILTER_LEN) {
    saddr: (slice, SADDR_FIELD),
    daddr: (slice, DADDR_FIELD),
    family: (u16, FAMILY_FIELD),
    splen: (u8, SPLEN_FIELD),
    dplen: (u8, DPLEN_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<AddressFilterBuffer<&T>> for AddressFilter {
    fn parse(buf: &AddressFilterBuffer<&T>) -> Result<Self, DecodeError> {
        let saddr = Address::parse(&AddressBuffer::new(&buf.saddr()))
            .context("failed to parse saddr address")?;
        let daddr = Address::parse(&AddressBuffer::new(&buf.daddr()))
            .context("failed to parse daddr address")?;
        Ok(AddressFilter {
            saddr,
            daddr,
            family: buf.family(),
            splen: buf.splen(),
            dplen: buf.dplen()
        })
    }
}

impl Emitable for AddressFilter {
    fn buffer_len(&self) -> usize {
        XFRM_ADDRESS_FILTER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = AddressFilterBuffer::new(buffer);
        self.saddr.emit(buffer.saddr_mut());
        self.daddr.emit(buffer.daddr_mut());
        buffer.set_family(self.family);
        buffer.set_splen(self.splen);
        buffer.set_dplen(self.dplen);
    }
}
