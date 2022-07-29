// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const POLICY_FLUSH_HEADER_LEN: usize = 0; // no message data, just potential attributes

buffer!(FlushMessageBuffer(POLICY_FLUSH_HEADER_LEN) {
    attributes: (slice, POLICY_FLUSH_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> FlushMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
