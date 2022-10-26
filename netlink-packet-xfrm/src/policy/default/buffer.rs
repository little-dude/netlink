// SPDX-License-Identifier: MIT

use crate::XFRM_USER_POLICY_DEFAULT_LEN;

use netlink_packet_utils::{buffer, DecodeError};

pub const POLICY_DEFAULT_HEADER_LEN: usize = XFRM_USER_POLICY_DEFAULT_LEN;

buffer!(DefaultMessageBuffer(POLICY_DEFAULT_HEADER_LEN) {
    user_policy: (slice, 0..XFRM_USER_POLICY_DEFAULT_LEN)
});
