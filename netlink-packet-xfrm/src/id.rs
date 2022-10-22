// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{Address, AddressBuffer, XFRM_ADDRESS_LEN};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Id {
    pub daddr: Address,
    pub spi: u32, // big-endian
    pub proto: u8,
}

pub const XFRM_ID_LEN: usize = (XFRM_ADDRESS_LEN + 5 + 7) & !7; // 24

buffer!(IdBuffer(XFRM_ID_LEN) {
    daddr: (slice, 0..XFRM_ADDRESS_LEN),
    spi: (u32, XFRM_ADDRESS_LEN..XFRM_ADDRESS_LEN+4),
    proto: (u8, XFRM_ADDRESS_LEN+4)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<IdBuffer<&T>> for Id {
    fn parse(buf: &IdBuffer<&T>) -> Result<Self, DecodeError> {
        let daddr = Address::parse(&AddressBuffer::new(&buf.daddr()))
            .context("failed to parse Address in Id")?;
        Ok(Id {
            daddr,
            spi: u32::from_be(buf.spi()),
            proto: buf.proto(),
        })
    }
}

impl Emitable for Id {
    fn buffer_len(&self) -> usize {
        XFRM_ID_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = IdBuffer::new(buffer);
        self.daddr.emit(buffer.daddr_mut());
        buffer.set_spi(self.spi.to_be());
        buffer.set_proto(self.proto);
    }
}
