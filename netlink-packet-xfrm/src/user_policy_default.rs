// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyDefault {
    pub input: u8,
    pub forward: u8,
    pub output: u8,
}

pub const XFRM_USER_POLICY_DEFAULT_LEN: usize = 3;

buffer!(UserPolicyDefaultBuffer(XFRM_USER_POLICY_DEFAULT_LEN) {
    input: (u8, 0),
    forward: (u8, 1),
    output: (u8, 2)
});

impl<T: AsRef<[u8]>> Parseable<UserPolicyDefaultBuffer<T>> for UserPolicyDefault {
    fn parse(buf: &UserPolicyDefaultBuffer<T>) -> Result<Self, DecodeError> {
        Ok(UserPolicyDefault {
            input: buf.input(),
            forward: buf.forward(),
            output: buf.output(),
        })
    }
}

impl Emitable for UserPolicyDefault {
    fn buffer_len(&self) -> usize {
        XFRM_USER_POLICY_DEFAULT_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserPolicyDefaultBuffer::new(buffer);
        buffer.set_input(self.input);
        buffer.set_forward(self.forward);
        buffer.set_output(self.output);
    }
}
