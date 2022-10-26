// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserOffloadDev {
    pub ifindex: i32, /* "int" in iproute2 */
    pub flags: u8,
}

pub const XFRM_USER_OFFLOAD_DEV_LEN: usize = 8;

buffer!(UserOffloadDevBuffer(XFRM_USER_OFFLOAD_DEV_LEN) {
    ifindex: (i32, 0..4),
    flags: (u8, 4)
    /* 3 bytes padding */
});

impl<T: AsRef<[u8]>> Parseable<UserOffloadDevBuffer<T>> for UserOffloadDev {
    fn parse(buf: &UserOffloadDevBuffer<T>) -> Result<Self, DecodeError> {
        Ok(UserOffloadDev {
            ifindex: buf.ifindex(),
            flags: buf.flags(),
        })
    }
}

impl Emitable for UserOffloadDev {
    fn buffer_len(&self) -> usize {
        XFRM_USER_OFFLOAD_DEV_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserOffloadDevBuffer::new(buffer);
        buffer.set_ifindex(self.ifindex);
        buffer.set_flags(self.flags);
    }
}
