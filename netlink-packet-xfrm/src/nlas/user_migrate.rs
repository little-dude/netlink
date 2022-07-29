// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address,
    AddressBuffer,
    XFRM_ADDRESS_LEN,
};

use netlink_packet_utils::{
    buffer,
    traits::*,
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserMigrate {
    pub old_daddr: Address,
    pub old_saddr: Address,
    pub new_daddr: Address,
    pub new_saddr: Address,
    pub proto: u8,
    pub mode: u8,
    pub reserved: u16,
    pub reqid: u32,
    pub old_family: u16,
    pub new_family: u16
}

const OLD_DADDR_FIELD: Range<usize>  = 0..XFRM_ADDRESS_LEN;
const OLD_SADDR_FIELD: Range<usize>  = OLD_DADDR_FIELD.end..(OLD_DADDR_FIELD.end + XFRM_ADDRESS_LEN);
const NEW_DADDR_FIELD: Range<usize>  = OLD_SADDR_FIELD.end..(OLD_SADDR_FIELD.end + XFRM_ADDRESS_LEN);
const NEW_SADDR_FIELD: Range<usize>  = NEW_DADDR_FIELD.end..(NEW_DADDR_FIELD.end + XFRM_ADDRESS_LEN);
const PROTO_FIELD: usize             = NEW_SADDR_FIELD.end;
const MODE_FIELD: usize              = PROTO_FIELD + 1;
const RESERVED_FIELD: Range<usize>   = (MODE_FIELD + 1)..(MODE_FIELD + 1 + 2);
const REQID_FIELD: Range<usize>      = RESERVED_FIELD.end..(RESERVED_FIELD.end + 4);
const OLD_FAMILY_FIELD: Range<usize> = REQID_FIELD.end..(REQID_FIELD.end + 2);
const NEW_FAMILY_FIELD: Range<usize> = OLD_FAMILY_FIELD.end..(OLD_FAMILY_FIELD.end + 2);

pub const XFRM_USER_MIGRATE_LEN: usize = NEW_FAMILY_FIELD.end; // 76

buffer!(UserMigrateBuffer(XFRM_USER_MIGRATE_LEN) {
    old_daddr: (slice, OLD_DADDR_FIELD),
    old_saddr: (slice, OLD_SADDR_FIELD),
    new_daddr: (slice, NEW_DADDR_FIELD),
    new_saddr: (slice, NEW_SADDR_FIELD),
    proto: (u8, PROTO_FIELD),
    mode: (u8, MODE_FIELD),
    reserved: (u16, RESERVED_FIELD),
    reqid: (u32, REQID_FIELD),
    old_family: (u16, OLD_FAMILY_FIELD),
    new_family: (u16, NEW_FAMILY_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserMigrateBuffer<&T>> for UserMigrate {
    fn parse(buf: &UserMigrateBuffer<&T>) -> Result<Self, DecodeError> {
        let old_daddr = Address::parse(&AddressBuffer::new(&buf.old_daddr()))
            .context("failed to parse old_daddr address")?;
        let old_saddr = Address::parse(&AddressBuffer::new(&buf.old_saddr()))
            .context("failed to parse old_saddr address")?;
        let new_daddr = Address::parse(&AddressBuffer::new(&buf.new_daddr()))
            .context("failed to parse new_daddr address")?;
        let new_saddr = Address::parse(&AddressBuffer::new(&buf.new_saddr()))
            .context("failed to parse new_saddr address")?;
        Ok(UserMigrate {
            old_daddr,
            old_saddr,
            new_daddr,
            new_saddr,
            proto: buf.proto(),
            mode: buf.mode(),
            reserved: buf.reserved(),
            reqid: buf.reqid(),
            old_family: buf.old_family(),
            new_family: buf.new_family()
        })
    }
}

impl Emitable for UserMigrate {
    fn buffer_len(&self) -> usize {
        XFRM_USER_MIGRATE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserMigrateBuffer::new(buffer);
        self.old_daddr.emit(buffer.old_daddr_mut());
        self.old_saddr.emit(buffer.old_saddr_mut());
        self.new_daddr.emit(buffer.new_daddr_mut());
        self.new_saddr.emit(buffer.new_saddr_mut());
        buffer.set_proto(self.proto);
        buffer.set_mode(self.mode);
        buffer.set_reserved(self.reserved);
        buffer.set_reqid(self.reqid);
        buffer.set_old_family(self.old_family);
        buffer.set_new_family(self.new_family);
    }
}
