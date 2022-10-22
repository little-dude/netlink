// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address, AddressBuffer, UserSaId, UserSaIdBuffer, XFRM_ADDRESS_LEN, XFRM_USER_SA_ID_LEN,
};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AsyncEventId {
    pub sa_id: UserSaId,
    pub saddr: Address,
    pub flags: u32,
    pub reqid: u32,
}

const SA_ID_FIELD: Range<usize> = 0..XFRM_USER_SA_ID_LEN;
const SADDR_FIELD: Range<usize> = SA_ID_FIELD.end..(SA_ID_FIELD.end + XFRM_ADDRESS_LEN);
const FLAGS_FIELD: Range<usize> = SADDR_FIELD.end..(SADDR_FIELD.end + 4);
const REQID_FIELD: Range<usize> = FLAGS_FIELD.end..(FLAGS_FIELD.end + 4);

pub const XFRM_ASYNC_EVENT_ID_LEN: usize = (REQID_FIELD.end + 7) & !7; // 48

buffer!(AsyncEventIdBuffer(XFRM_ASYNC_EVENT_ID_LEN) {
    sa_id: (slice, SA_ID_FIELD),
    saddr: (slice, SADDR_FIELD),
    flags: (u32, FLAGS_FIELD),
    reqid: (u32, REQID_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<AsyncEventIdBuffer<&T>> for AsyncEventId {
    fn parse(buf: &AsyncEventIdBuffer<&T>) -> Result<Self, DecodeError> {
        let sa_id =
            UserSaId::parse(&UserSaIdBuffer::new(&buf.sa_id())).context("failed to parse sa_id")?;
        let saddr =
            Address::parse(&AddressBuffer::new(&buf.saddr())).context("failed to parse saddr")?;
        Ok(AsyncEventId {
            sa_id,
            saddr,
            flags: buf.flags(),
            reqid: buf.reqid(),
        })
    }
}

impl Emitable for AsyncEventId {
    fn buffer_len(&self) -> usize {
        XFRM_ASYNC_EVENT_ID_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = AsyncEventIdBuffer::new(buffer);
        self.sa_id.emit(buffer.sa_id_mut());
        self.saddr.emit(buffer.saddr_mut());
        buffer.set_flags(self.flags);
        buffer.set_reqid(self.reqid);
    }
}
