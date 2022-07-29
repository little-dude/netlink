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
pub struct UserKmAddress {
    pub local: Address,
    pub remote: Address,
    pub reserved: u32,
    pub family: u16
}

const LOCAL_FIELD: Range<usize>    = 0..XFRM_ADDRESS_LEN;
const REMOTE_FIELD: Range<usize>   = LOCAL_FIELD.end..(LOCAL_FIELD.end + XFRM_ADDRESS_LEN);
const RESERVED_FIELD: Range<usize> = REMOTE_FIELD.end..(REMOTE_FIELD.end + 4);
const FAMILY_FIELD: Range<usize>   = RESERVED_FIELD.end..(RESERVED_FIELD.end + 2);

pub const XFRM_USER_KMADDRESS_LEN: usize = (FAMILY_FIELD.end + 7) & !7; // 40

buffer!(UserKmAddressBuffer(XFRM_USER_KMADDRESS_LEN) {
    local: (slice, LOCAL_FIELD),
    remote: (slice, REMOTE_FIELD),
    reserved: (u32, RESERVED_FIELD),
    family: (u16, FAMILY_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserKmAddressBuffer<&T>> for UserKmAddress {
    fn parse(buf: &UserKmAddressBuffer<&T>) -> Result<Self, DecodeError> {
        let local = Address::parse(&AddressBuffer::new(&buf.local()))
            .context("failed to parse local address")?;
        let remote = Address::parse(&AddressBuffer::new(&buf.remote()))
            .context("failed to parse remote address")?;
        Ok(UserKmAddress {
            local,
            remote,
            reserved: buf.reserved(),
            family: buf.family()
        })
    }
}

impl Emitable for UserKmAddress {
    fn buffer_len(&self) -> usize {
        XFRM_USER_KMADDRESS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserKmAddressBuffer::new(buffer);
        self.local.emit(buffer.local_mut());
        self.remote.emit(buffer.remote_mut());
        buffer.set_reserved(self.reserved);
        buffer.set_family(self.family);
    }
}
