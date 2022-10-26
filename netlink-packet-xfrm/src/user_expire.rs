// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{UserSaInfo, UserSaInfoBuffer, XFRM_USER_SA_INFO_LEN};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserExpire {
    pub state: UserSaInfo,
    pub hard: u8,
}

const STATE_FIELD: Range<usize> = 0..XFRM_USER_SA_INFO_LEN;
const HARD_FIELD: usize = STATE_FIELD.end;

pub const XFRM_USER_EXPIRE_LEN: usize = (XFRM_USER_SA_INFO_LEN + 1 + 7) & !7; // 232

buffer!(UserExpireBuffer(XFRM_USER_EXPIRE_LEN) {
    state: (slice, STATE_FIELD),
    hard: (u8, HARD_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserExpireBuffer<&T>> for UserExpire {
    fn parse(buf: &UserExpireBuffer<&T>) -> Result<Self, DecodeError> {
        let state = UserSaInfo::parse(&UserSaInfoBuffer::new(&buf.state()))
            .context("failed to parse user sa info")?;
        Ok(UserExpire {
            state,
            hard: buf.hard(),
        })
    }
}

impl Emitable for UserExpire {
    fn buffer_len(&self) -> usize {
        XFRM_USER_EXPIRE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserExpireBuffer::new(buffer);
        self.state.emit(buffer.state_mut());
        buffer.set_hard(self.hard);
    }
}
