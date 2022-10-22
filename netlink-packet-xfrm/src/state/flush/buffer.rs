// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, DecodeError};

pub const STATE_FLUSH_HEADER_LEN: usize = 1;

buffer!(FlushMessageBuffer(STATE_FLUSH_HEADER_LEN) {
    protocol: (u8, 0)
});
