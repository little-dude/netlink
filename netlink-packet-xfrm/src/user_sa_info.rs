// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{
    Address, AddressBuffer, Id, IdBuffer, Lifetime, LifetimeBuffer, LifetimeConfig,
    LifetimeConfigBuffer, Selector, SelectorBuffer, Stats, StatsBuffer, XFRM_ADDRESS_LEN,
    XFRM_ID_LEN, XFRM_LIFETIME_CONFIG_LEN, XFRM_LIFETIME_LEN, XFRM_SELECTOR_LEN, XFRM_STATS_LEN,
};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserSaInfo {
    pub selector: Selector,
    pub id: Id,
    pub saddr: Address,
    pub lifetime_cfg: LifetimeConfig,
    pub lifetime_cur: Lifetime,
    pub stats: Stats,
    pub seq: u32,
    pub reqid: u32,
    pub family: u16,
    pub mode: u8,
    pub replay_window: u8,
    pub flags: u8,
}

const SELECTOR_FIELD: Range<usize> = 0..XFRM_SELECTOR_LEN;
const ID_FIELD: Range<usize> = SELECTOR_FIELD.end..(SELECTOR_FIELD.end + XFRM_ID_LEN);
const SADDR_FIELD: Range<usize> = ID_FIELD.end..(ID_FIELD.end + XFRM_ADDRESS_LEN);
const LIFETIME_CFG_FIELD: Range<usize> =
    SADDR_FIELD.end..(SADDR_FIELD.end + XFRM_LIFETIME_CONFIG_LEN);
const LIFETIME_CUR_FIELD: Range<usize> =
    LIFETIME_CFG_FIELD.end..(LIFETIME_CFG_FIELD.end + XFRM_LIFETIME_LEN);
const STATS_FIELD: Range<usize> = LIFETIME_CUR_FIELD.end..(LIFETIME_CUR_FIELD.end + XFRM_STATS_LEN);
const SEQ_FIELD: Range<usize> = STATS_FIELD.end..(STATS_FIELD.end + 4);
const REQID_FIELD: Range<usize> = SEQ_FIELD.end..(SEQ_FIELD.end + 4);
const FAMILY_FIELD: Range<usize> = REQID_FIELD.end..(REQID_FIELD.end + 2);
const MODE_FIELD: usize = FAMILY_FIELD.end;
const REPLAY_WINDOW_FIELD: usize = MODE_FIELD + 1;
const FLAGS_FIELD: usize = REPLAY_WINDOW_FIELD + 1;

pub const XFRM_USER_SA_INFO_LEN: usize = FLAGS_FIELD + 8; //224

buffer!(UserSaInfoBuffer(XFRM_USER_SA_INFO_LEN) {
    selector: (slice, SELECTOR_FIELD),
    id: (slice, ID_FIELD),
    saddr: (slice, SADDR_FIELD),
    lifetime_cfg: (slice, LIFETIME_CFG_FIELD),
    lifetime_cur: (slice, LIFETIME_CUR_FIELD),
    stats: (slice, STATS_FIELD),
    seq: (u32, SEQ_FIELD),
    reqid: (u32, REQID_FIELD),
    family: (u16, FAMILY_FIELD),
    mode: (u8, MODE_FIELD),
    replay_window: (u8, REPLAY_WINDOW_FIELD),
    flags: (u8, FLAGS_FIELD)
    /* 8 bytes padding */
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserSaInfoBuffer<&T>> for UserSaInfo {
    fn parse(buf: &UserSaInfoBuffer<&T>) -> Result<Self, DecodeError> {
        let selector = Selector::parse(&SelectorBuffer::new(&buf.selector()))
            .context("failed to parse selector")?;
        let id = Id::parse(&IdBuffer::new(&buf.id())).context("failed to parse id")?;
        let saddr =
            Address::parse(&AddressBuffer::new(&buf.saddr())).context("failed to parse saddr")?;
        let lifetime_cfg = LifetimeConfig::parse(&LifetimeConfigBuffer::new(&buf.lifetime_cfg()))
            .context("failed to parse lifetime config")?;
        let lifetime_cur = Lifetime::parse(&LifetimeBuffer::new(&buf.lifetime_cur()))
            .context("failed to parse lifetime current")?;
        let stats =
            Stats::parse(&StatsBuffer::new(&buf.stats())).context("failed to parse stats")?;
        Ok(UserSaInfo {
            selector,
            id,
            saddr,
            lifetime_cfg,
            lifetime_cur,
            stats,
            seq: buf.seq(),
            reqid: buf.reqid(),
            family: buf.family(),
            mode: buf.mode(),
            replay_window: buf.replay_window(),
            flags: buf.flags(),
        })
    }
}

impl Emitable for UserSaInfo {
    fn buffer_len(&self) -> usize {
        XFRM_USER_SA_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserSaInfoBuffer::new(buffer);
        self.selector.emit(buffer.selector_mut());
        self.id.emit(buffer.id_mut());
        self.saddr.emit(buffer.saddr_mut());
        self.lifetime_cfg.emit(buffer.lifetime_cfg_mut());
        self.lifetime_cur.emit(buffer.lifetime_cur_mut());
        self.stats.emit(buffer.stats_mut());
        buffer.set_seq(self.seq);
        buffer.set_reqid(self.reqid);
        buffer.set_family(self.family);
        buffer.set_mode(self.mode);
        buffer.set_replay_window(self.replay_window);
        buffer.set_flags(self.flags);
    }
}
