// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{Selector, SelectorBuffer, XFRM_SELECTOR_LEN};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyId {
    pub selector: Selector,
    pub index: u32,
    pub direction: u8,
}

const SELECTOR_FIELD: Range<usize> = 0..XFRM_SELECTOR_LEN;
const INDEX_FIELD: Range<usize> = SELECTOR_FIELD.end..(SELECTOR_FIELD.end + 4);
const DIRECTION_FIELD: usize = INDEX_FIELD.end;

pub const XFRM_USER_POLICY_ID_LEN: usize = (DIRECTION_FIELD + 7) & !7; // 64

buffer!(UserPolicyIdBuffer(XFRM_USER_POLICY_ID_LEN) {
    selector: (slice, SELECTOR_FIELD),
    index: (u32, INDEX_FIELD),
    direction: (u8, DIRECTION_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserPolicyIdBuffer<&T>> for UserPolicyId {
    fn parse(buf: &UserPolicyIdBuffer<&T>) -> Result<Self, DecodeError> {
        let selector = Selector::parse(&SelectorBuffer::new(&buf.selector()))
            .context("failed to parse selector")?;
        Ok(UserPolicyId {
            selector,
            index: buf.index(),
            direction: buf.direction(),
        })
    }
}

impl Emitable for UserPolicyId {
    fn buffer_len(&self) -> usize {
        XFRM_USER_POLICY_ID_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserPolicyIdBuffer::new(buffer);
        self.selector.emit(buffer.selector_mut());
        buffer.set_index(self.index);
        buffer.set_direction(self.direction);
    }
}
