// SPDX-License-Identifier: MIT

use crate::XFRM_USER_SA_INFO_LEN;

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const STATE_MODIFY_HEADER_LEN: usize = XFRM_USER_SA_INFO_LEN;

buffer!(ModifyMessageBuffer(STATE_MODIFY_HEADER_LEN) {
    user_sa_info: (slice, 0..STATE_MODIFY_HEADER_LEN),
    attributes: (slice, STATE_MODIFY_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> ModifyMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
