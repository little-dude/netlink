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
pub struct UserSaId {
    pub daddr: Address,
    pub spi: u32, // big-endian
    pub family: u16,
    pub proto: u8
}

const DADDR_FIELD: Range<usize>  = 0..XFRM_ADDRESS_LEN;
const SPI_FIELD: Range<usize>    = DADDR_FIELD.end..(DADDR_FIELD.end + 4);
const FAMILY_FIELD: Range<usize> = SPI_FIELD.end..(SPI_FIELD.end + 2);
const PROTO_FIELD: usize         = FAMILY_FIELD.end;

pub const XFRM_USER_SA_ID_LEN: usize = (PROTO_FIELD + 7) & !7; // 24

buffer!(UserSaIdBuffer(XFRM_USER_SA_ID_LEN) {
    daddr: (slice, DADDR_FIELD),
    spi: (u32, SPI_FIELD),
    family: (u16, FAMILY_FIELD),
    proto: (u8, PROTO_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserSaIdBuffer<&T>> for UserSaId {
    fn parse(buf: &UserSaIdBuffer<&T>) -> Result<Self, DecodeError> {
        let daddr = Address::parse(&AddressBuffer::new(&buf.daddr()))
            .context("failed to parse daddr")?;
        Ok(UserSaId {
            daddr,
            spi: u32::from_be(buf.spi()),
            family: buf.family(),
            proto: buf.proto()
        })
    }
}

impl Emitable for UserSaId {
    fn buffer_len(&self) -> usize {
        XFRM_USER_SA_ID_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserSaIdBuffer::new(buffer);
        self.daddr.emit(buffer.daddr_mut());
        buffer.set_spi(self.spi.to_be());
        buffer.set_family(self.family);
        buffer.set_proto(self.proto);
    }
}
