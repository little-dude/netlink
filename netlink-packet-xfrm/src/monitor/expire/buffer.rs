// SPDX-License-Identifier: MIT

use crate::XFRM_USER_EXPIRE_LEN;

use netlink_packet_utils::{buffer, DecodeError};

pub const MONITOR_EXPIRE_HEADER_LEN: usize = XFRM_USER_EXPIRE_LEN;

buffer!(ExpireMessageBuffer(MONITOR_EXPIRE_HEADER_LEN) {
    expire: (slice, 0..MONITOR_EXPIRE_HEADER_LEN)
});
