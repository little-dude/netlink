// SPDX-License-Identifier: MIT

use crate::XFRM_USER_POLICY_INFO_LEN;

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const POLICY_MODIFY_HEADER_LEN: usize = XFRM_USER_POLICY_INFO_LEN;

buffer!(ModifyMessageBuffer(POLICY_MODIFY_HEADER_LEN) {
    user_policy_info: (slice, 0..POLICY_MODIFY_HEADER_LEN),
    attributes: (slice, POLICY_MODIFY_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> ModifyMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
