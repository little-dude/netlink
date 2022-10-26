// SPDX-License-Identifier: MIT

use crate::XFRM_USER_SPI_INFO_LEN;

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const STATE_ALLOC_SPI_HEADER_LEN: usize = XFRM_USER_SPI_INFO_LEN;

buffer!(AllocSpiMessageBuffer(STATE_ALLOC_SPI_HEADER_LEN) {
    spi_info: (slice, 0..STATE_ALLOC_SPI_HEADER_LEN),
    attributes: (slice, STATE_ALLOC_SPI_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> AllocSpiMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
