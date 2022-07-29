// SPDX-License-Identifier: MIT

use crate::XFRM_USER_REPORT_LEN;

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const MONITOR_REPORT_HEADER_LEN: usize = XFRM_USER_REPORT_LEN;

buffer!(ReportMessageBuffer(MONITOR_REPORT_HEADER_LEN) {
    report: (slice, 0..MONITOR_REPORT_HEADER_LEN),
    attributes: (slice, MONITOR_REPORT_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> ReportMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
