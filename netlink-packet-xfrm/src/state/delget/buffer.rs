// SPDX-License-Identifier: MIT

use crate::XFRM_USER_SA_ID_LEN;

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

// The same buffer handles state delete and get messages

pub const STATE_DELGET_HEADER_LEN: usize = XFRM_USER_SA_ID_LEN;

buffer!(DelGetMessageBuffer(STATE_DELGET_HEADER_LEN) {
    user_sa_id: (slice, 0..STATE_DELGET_HEADER_LEN),
    attributes: (slice, STATE_DELGET_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> DelGetMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}

// For State dump request with AddressFilter (no header, just attrib)

pub const STATE_GET_DUMP_HEADER_LEN: usize = 0;

buffer!(GetDumpMessageBuffer(STATE_GET_DUMP_HEADER_LEN) {
    attributes: (slice, STATE_GET_DUMP_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> GetDumpMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
