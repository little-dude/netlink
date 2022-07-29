// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    UserPolicyInfo,
    UserPolicyInfoBuffer,
    XFRM_USER_POLICY_INFO_LEN,
};

use netlink_packet_utils::{
    buffer,
    traits::*,
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyExpire {
    pub pol: UserPolicyInfo,
    pub hard: u8
}

const POL_FIELD: Range<usize> = 0..XFRM_USER_POLICY_INFO_LEN;
const HARD_FIELD: usize       = POL_FIELD.end;

pub const XFRM_USER_POLICY_EXPIRE_LEN: usize = (XFRM_USER_POLICY_INFO_LEN + 1 + 7) & !7; // 176

buffer!(UserPolicyExpireBuffer(XFRM_USER_POLICY_EXPIRE_LEN) {
    pol: (slice, POL_FIELD),
    hard: (u8, HARD_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserPolicyExpireBuffer<&T>> for UserPolicyExpire {
    fn parse(buf: &UserPolicyExpireBuffer<&T>) -> Result<Self, DecodeError> {
        let pol = UserPolicyInfo::parse(&UserPolicyInfoBuffer::new(&buf.pol()))
            .context("failed to parse user policy info")?;
        Ok(UserPolicyExpire {
            pol,
            hard: buf.hard()
        })
    }
}

impl Emitable for UserPolicyExpire {
    fn buffer_len(&self) -> usize {
        XFRM_USER_POLICY_EXPIRE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserPolicyExpireBuffer::new(buffer);
        self.pol.emit(buffer.pol_mut());
        buffer.set_hard(self.hard);
    }
}
