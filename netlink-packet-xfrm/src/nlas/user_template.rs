// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address,
    AddressBuffer,
    Id,
    IdBuffer,
    XFRM_ID_LEN,
    XFRM_ADDRESS_LEN,
};

use netlink_packet_utils::{
    buffer,
    traits::*,
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UserTemplate {
    pub id: Id,
    pub family: u16,
    pub saddr: Address,
    pub reqid: u32,
    pub mode: u8,
    pub share: u8,
    pub optional: u8,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32
}

const ID_FIELD: Range<usize>     = 0..XFRM_ID_LEN;
const FAMILY_FIELD: Range<usize> = ID_FIELD.end..(ID_FIELD.end + 2);
const SADDR_FIELD: Range<usize>  = (FAMILY_FIELD.end + 2)..(FAMILY_FIELD.end + 2 + XFRM_ADDRESS_LEN);
const REQID_FIELD: Range<usize>  = SADDR_FIELD.end..(SADDR_FIELD.end + 4);
const MODE_FIELD: usize          = REQID_FIELD.end;
const SHARE_FIELD: usize         = MODE_FIELD + 1;
const OPTIONAL_FIELD: usize      = SHARE_FIELD + 1;
const AALGOS_FIELD: Range<usize> = (OPTIONAL_FIELD + 2)..(OPTIONAL_FIELD + 2 + 4);
const EALGOS_FIELD: Range<usize> = AALGOS_FIELD.end..(AALGOS_FIELD.end + 4);
const CALGOS_FIELD: Range<usize> = EALGOS_FIELD.end..(EALGOS_FIELD.end + 4);

pub const XFRM_USER_TEMPLATE_LEN: usize = CALGOS_FIELD.end; //64

buffer!(UserTemplateBuffer(XFRM_USER_TEMPLATE_LEN) {
    id: (slice, ID_FIELD),
    family: (u16, FAMILY_FIELD),
    /* 2 bytes padding */
    saddr: (slice, SADDR_FIELD),
    reqid: (u32, REQID_FIELD),
    mode: (u8, MODE_FIELD),
    share: (u8, SHARE_FIELD),
    optional: (u8, OPTIONAL_FIELD),
    /* 1 byte padding */
    aalgos: (u32, AALGOS_FIELD),
    ealgos: (u32, EALGOS_FIELD),
    calgos: (u32, CALGOS_FIELD)
});

impl Default for UserTemplate {
    fn default() -> Self {
        UserTemplate {
            id: Id::default(),
            family: 0,
            saddr: Address::default(),
            reqid: 0,
            mode: 0,
            share: 0,
            optional: 0,
            aalgos: u32::MAX,
            ealgos: u32::MAX,
            calgos: u32::MAX,
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserTemplateBuffer<&T>> for UserTemplate {
    fn parse(buf: &UserTemplateBuffer<&T>) -> Result<Self, DecodeError> {
        let id = Id::parse(&IdBuffer::new(&buf.id()))
            .context("failed to parse Id in UserTemplate")?;
        let saddr = Address::parse(&AddressBuffer::new(&buf.saddr()))
            .context("failed to parse Address in UserTemplate")?;
        Ok(UserTemplate {
            id,
            family: buf.family(),
            saddr,
            reqid: buf.reqid(),
            mode: buf.mode(),
            share: buf.share(),
            optional: buf.optional(),
            aalgos: buf.aalgos(),
            ealgos: buf.ealgos(),
            calgos: buf.calgos()
        })
    }
}

impl Emitable for UserTemplate {
    fn buffer_len(&self) -> usize {
        XFRM_USER_TEMPLATE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserTemplateBuffer::new(buffer);
        self.id.emit(buffer.id_mut());
        buffer.set_family(self.family);
        self.saddr.emit(buffer.saddr_mut());
        buffer.set_reqid(self.reqid);
        buffer.set_mode(self.mode);
        buffer.set_share(self.share);
        buffer.set_optional(self.optional);
        buffer.set_aalgos(self.aalgos);
        buffer.set_ealgos(self.ealgos);
        buffer.set_calgos(self.calgos);
    }
}
