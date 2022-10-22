// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{Selector, SelectorBuffer, XFRM_SELECTOR_LEN};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserReport {
    pub proto: u8,
    pub selector: Selector,
}

const SELECTOR_FIELD: Range<usize> = 4..(4 + XFRM_SELECTOR_LEN);

pub const XFRM_USER_REPORT_LEN: usize = SELECTOR_FIELD.end; // 60 (not rounded up to 64)

buffer!(UserReportBuffer(XFRM_USER_REPORT_LEN) {
    proto: (u8, 0),
    /* 3 bytes padding */
    selector: (slice, SELECTOR_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserReportBuffer<&T>> for UserReport {
    fn parse(buf: &UserReportBuffer<&T>) -> Result<Self, DecodeError> {
        let selector = Selector::parse(&SelectorBuffer::new(&buf.selector()))
            .context("failed to parse selector")?;
        Ok(UserReport {
            proto: buf.proto(),
            selector,
        })
    }
}

impl Emitable for UserReport {
    fn buffer_len(&self) -> usize {
        XFRM_USER_REPORT_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserReportBuffer::new(buffer);
        buffer.set_proto(self.proto);
        self.selector.emit(buffer.selector_mut());
    }
}
