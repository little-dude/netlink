// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyType {
    pub ptype: u8,
    pub reserved1: u16,
    pub reserved2: u8,
}

pub const XFRM_USER_POLICY_TYPE_LEN: usize = 6; /* includes 2 bytes of padding */

buffer!(UserPolicyTypeBuffer(XFRM_USER_POLICY_TYPE_LEN) {
    ptype: (u8, 0),
    /* 1 byte padding */
    reserved1: (u16, 2..4),
    reserved2: (u8, 4),
    /* 1 byte padding */
});

impl<T: AsRef<[u8]>> Parseable<UserPolicyTypeBuffer<T>> for UserPolicyType {
    fn parse(buf: &UserPolicyTypeBuffer<T>) -> Result<Self, DecodeError> {
        Ok(UserPolicyType {
            ptype: buf.ptype(),
            reserved1: buf.reserved1(),
            reserved2: buf.reserved2(),
        })
    }
}

impl Emitable for UserPolicyType {
    fn buffer_len(&self) -> usize {
        XFRM_USER_POLICY_TYPE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserPolicyTypeBuffer::new(buffer);
        buffer.set_ptype(self.ptype);
        buffer.set_reserved1(self.reserved1);
        buffer.set_reserved2(self.reserved2);
    }
}
