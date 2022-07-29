// SPDX-License-Identifier: MIT

use crate::XFRM_USER_POLICY_EXPIRE_LEN;

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const MONITOR_POLICY_EXPIRE_HEADER_LEN: usize = XFRM_USER_POLICY_EXPIRE_LEN;

buffer!(PolicyExpireMessageBuffer(MONITOR_POLICY_EXPIRE_HEADER_LEN) {
    expire: (slice, 0..MONITOR_POLICY_EXPIRE_HEADER_LEN),
    attributes: (slice, MONITOR_POLICY_EXPIRE_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> PolicyExpireMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
