// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Lifetime, LifetimeBuffer, LifetimeConfig, LifetimeConfigBuffer, Selector, SelectorBuffer,
    XFRM_LIFETIME_CONFIG_LEN, XFRM_LIFETIME_LEN, XFRM_SELECTOR_LEN,
};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyInfo {
    pub selector: Selector,
    pub lifetime_cfg: LifetimeConfig,
    pub lifetime_cur: Lifetime,
    pub priority: u32,
    pub index: u32,
    pub direction: u8,
    pub action: u8,
    pub flags: u8,
    pub share: u8,
}

const SELECTOR_FIELD: Range<usize> = 0..XFRM_SELECTOR_LEN;
const LIFETIME_CFG_FIELD: Range<usize> =
    SELECTOR_FIELD.end..(SELECTOR_FIELD.end + XFRM_LIFETIME_CONFIG_LEN);
const LIFETIME_CUR_FIELD: Range<usize> =
    LIFETIME_CFG_FIELD.end..(LIFETIME_CFG_FIELD.end + XFRM_LIFETIME_LEN);
const PRIORITY_FIELD: Range<usize> = LIFETIME_CUR_FIELD.end..(LIFETIME_CUR_FIELD.end + 4);
const INDEX_FIELD: Range<usize> = PRIORITY_FIELD.end..(PRIORITY_FIELD.end + 4);
const DIRECTION_FIELD: usize = INDEX_FIELD.end;
const ACTION_FIELD: usize = DIRECTION_FIELD + 1;
const FLAGS_FIELD: usize = ACTION_FIELD + 1;
const SHARE_FIELD: usize = FLAGS_FIELD + 1;

pub const XFRM_USER_POLICY_INFO_LEN: usize = (SHARE_FIELD + 7) & !7; // 168

buffer!(UserPolicyInfoBuffer(XFRM_USER_POLICY_INFO_LEN) {
    selector: (slice, SELECTOR_FIELD),
    lifetime_cfg: (slice, LIFETIME_CFG_FIELD),
    lifetime_cur: (slice, LIFETIME_CUR_FIELD),
    priority: (u32, PRIORITY_FIELD),
    index: (u32, INDEX_FIELD),
    direction: (u8, DIRECTION_FIELD),
    action: (u8, ACTION_FIELD),
    flags: (u8, FLAGS_FIELD),
    share: (u8, SHARE_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserPolicyInfoBuffer<&T>> for UserPolicyInfo {
    fn parse(buf: &UserPolicyInfoBuffer<&T>) -> Result<Self, DecodeError> {
        let selector = Selector::parse(&SelectorBuffer::new(&buf.selector()))
            .context("failed to parse selector")?;
        let lifetime_cfg = LifetimeConfig::parse(&LifetimeConfigBuffer::new(&buf.lifetime_cfg()))
            .context("failed to parse lifetime config")?;
        let lifetime_cur = Lifetime::parse(&LifetimeBuffer::new(&buf.lifetime_cur()))
            .context("failed to parse lifetime current")?;
        Ok(UserPolicyInfo {
            selector,
            lifetime_cfg,
            lifetime_cur,
            priority: buf.priority(),
            index: buf.index(),
            direction: buf.direction(),
            action: buf.action(),
            flags: buf.flags(),
            share: buf.share(),
        })
    }
}

impl Emitable for UserPolicyInfo {
    fn buffer_len(&self) -> usize {
        XFRM_USER_POLICY_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserPolicyInfoBuffer::new(buffer);
        self.selector.emit(buffer.selector_mut());
        self.lifetime_cfg.emit(buffer.lifetime_cfg_mut());
        self.lifetime_cur.emit(buffer.lifetime_cur_mut());
        buffer.set_priority(self.priority);
        buffer.set_index(self.index);
        buffer.set_direction(self.direction);
        buffer.set_action(self.action);
        buffer.set_flags(self.flags);
        buffer.set_share(self.share);
    }
}
