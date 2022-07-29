// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const POLICY_NEW_SPD_INFO_HEADER_LEN: usize = 4;

buffer!(NewSpdInfoMessageBuffer(POLICY_NEW_SPD_INFO_HEADER_LEN) {
    flags: (u32, 0..4),
    attributes: (slice, POLICY_NEW_SPD_INFO_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> NewSpdInfoMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}

pub const POLICY_GET_SPD_INFO_HEADER_LEN: usize = 4;

buffer!(GetSpdInfoMessageBuffer(POLICY_GET_SPD_INFO_HEADER_LEN) {
    flags: (u32, 0..4)
});
