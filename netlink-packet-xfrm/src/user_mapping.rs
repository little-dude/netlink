// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address, AddressBuffer, UserSaId, UserSaIdBuffer, XFRM_ADDRESS_LEN, XFRM_USER_SA_ID_LEN,
};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserMapping {
    pub id: UserSaId,
    pub reqid: u32,
    pub old_saddr: Address,
    pub new_saddr: Address,
    pub old_sport: u16, // big-endian
    pub new_sport: u16, // big-endian
}

const ID_FIELD: Range<usize> = 0..XFRM_USER_SA_ID_LEN;
const REQID_FIELD: Range<usize> = ID_FIELD.end..(ID_FIELD.end + 4);
const OLD_SADDR_FIELD: Range<usize> = REQID_FIELD.end..(REQID_FIELD.end + XFRM_ADDRESS_LEN);
const NEW_SADDR_FIELD: Range<usize> = OLD_SADDR_FIELD.end..(OLD_SADDR_FIELD.end + XFRM_ADDRESS_LEN);
const OLD_SPORT_FIELD: Range<usize> = NEW_SADDR_FIELD.end..(NEW_SADDR_FIELD.end + 2);
const NEW_SPORT_FIELD: Range<usize> = OLD_SPORT_FIELD.end..(OLD_SPORT_FIELD.end + 2);

pub const XFRM_USER_MAPPING_LEN: usize = NEW_SPORT_FIELD.end; // 64

buffer!(UserMappingBuffer(XFRM_USER_MAPPING_LEN) {
    id: (slice, ID_FIELD),
    reqid: (u32, REQID_FIELD),
    old_saddr: (slice, OLD_SADDR_FIELD),
    new_saddr: (slice, NEW_SADDR_FIELD),
    old_sport: (u16, OLD_SPORT_FIELD),
    new_sport: (u16, NEW_SPORT_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserMappingBuffer<&T>> for UserMapping {
    fn parse(buf: &UserMappingBuffer<&T>) -> Result<Self, DecodeError> {
        let id = UserSaId::parse(&UserSaIdBuffer::new(&buf.id()))
            .context("failed to parse user sa id")?;
        let old_saddr = Address::parse(&AddressBuffer::new(&buf.old_saddr()))
            .context("failed to parse old saddr")?;
        let new_saddr = Address::parse(&AddressBuffer::new(&buf.new_saddr()))
            .context("failed to parse new saddr")?;
        Ok(UserMapping {
            id,
            reqid: buf.reqid(),
            old_saddr,
            new_saddr,
            old_sport: u16::from_be(buf.old_sport()),
            new_sport: u16::from_be(buf.new_sport()),
        })
    }
}

impl Emitable for UserMapping {
    fn buffer_len(&self) -> usize {
        XFRM_USER_MAPPING_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserMappingBuffer::new(buffer);
        self.id.emit(buffer.id_mut());
        buffer.set_reqid(self.reqid);
        self.old_saddr.emit(buffer.old_saddr_mut());
        self.new_saddr.emit(buffer.new_saddr_mut());
        buffer.set_old_sport(self.old_sport.to_be());
        buffer.set_new_sport(self.new_sport.to_be());
    }
}
