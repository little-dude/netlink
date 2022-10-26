// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address, AddressBuffer, Id, IdBuffer, Selector, SelectorBuffer, UserPolicyInfo,
    UserPolicyInfoBuffer, XFRM_ADDRESS_LEN, XFRM_ID_LEN, XFRM_SELECTOR_LEN,
    XFRM_USER_POLICY_INFO_LEN,
};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserAcquire {
    pub id: Id,
    pub saddr: Address,
    pub selector: Selector,
    pub policy: UserPolicyInfo,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
    pub seq: u32,
}

const ID_FIELD: Range<usize> = 0..XFRM_ID_LEN;
const SADDR_FIELD: Range<usize> = ID_FIELD.end..(ID_FIELD.end + XFRM_ADDRESS_LEN);
const SELECTOR_FIELD: Range<usize> = SADDR_FIELD.end..(SADDR_FIELD.end + XFRM_SELECTOR_LEN);
const POLICY_FIELD: Range<usize> =
    SELECTOR_FIELD.end..(SELECTOR_FIELD.end + XFRM_USER_POLICY_INFO_LEN);
const AALGOS_FIELD: Range<usize> = POLICY_FIELD.end..(POLICY_FIELD.end + 4);
const EALGOS_FIELD: Range<usize> = AALGOS_FIELD.end..(AALGOS_FIELD.end + 4);
const CALGOS_FIELD: Range<usize> = EALGOS_FIELD.end..(EALGOS_FIELD.end + 4);
const SEQ_FIELD: Range<usize> = CALGOS_FIELD.end..(CALGOS_FIELD.end + 4);

pub const XFRM_USER_ACQUIRE_LEN: usize = (SEQ_FIELD.end + 7) & !7; // 280

buffer!(UserAcquireBuffer(XFRM_USER_ACQUIRE_LEN) {
    id: (slice, ID_FIELD),
    saddr: (slice, SADDR_FIELD),
    selector: (slice, SELECTOR_FIELD),
    policy: (slice, POLICY_FIELD),
    aalgos: (u32, AALGOS_FIELD),
    ealgos: (u32, EALGOS_FIELD),
    calgos: (u32, CALGOS_FIELD),
    seq: (u32, SEQ_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserAcquireBuffer<&T>> for UserAcquire {
    fn parse(buf: &UserAcquireBuffer<&T>) -> Result<Self, DecodeError> {
        let id = Id::parse(&IdBuffer::new(&buf.id())).context("failed to parse id")?;
        let saddr =
            Address::parse(&AddressBuffer::new(&buf.saddr())).context("failed to parse saddr")?;
        let selector = Selector::parse(&SelectorBuffer::new(&buf.selector()))
            .context("failed to parse selector")?;
        let policy = UserPolicyInfo::parse(&UserPolicyInfoBuffer::new(&buf.policy()))
            .context("failed to parse policy")?;
        Ok(UserAcquire {
            id,
            saddr,
            selector,
            policy,
            aalgos: buf.aalgos(),
            ealgos: buf.ealgos(),
            calgos: buf.calgos(),
            seq: buf.seq(),
        })
    }
}

impl Emitable for UserAcquire {
    fn buffer_len(&self) -> usize {
        XFRM_USER_ACQUIRE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserAcquireBuffer::new(buffer);
        self.id.emit(buffer.id_mut());
        self.saddr.emit(buffer.saddr_mut());
        self.selector.emit(buffer.selector_mut());
        self.policy.emit(buffer.policy_mut());
        buffer.set_aalgos(self.aalgos);
        buffer.set_ealgos(self.ealgos);
        buffer.set_calgos(self.calgos);
        buffer.set_seq(self.seq);
    }
}
