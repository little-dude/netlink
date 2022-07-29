// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const STATE_NEW_SAD_INFO_HEADER_LEN: usize = 4;

buffer!(NewSadInfoMessageBuffer(STATE_NEW_SAD_INFO_HEADER_LEN) {
    flags: (u32, 0..4),
    attributes: (slice, STATE_NEW_SAD_INFO_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> NewSadInfoMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}

pub const STATE_GET_SAD_INFO_HEADER_LEN: usize = 4;

buffer!(GetSadInfoMessageBuffer(STATE_GET_SAD_INFO_HEADER_LEN) {
    flags: (u32, 0..4)
});
