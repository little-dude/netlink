// SPDX-License-Identifier: MIT

use crate::XFRM_USER_POLICY_ID_LEN;

use netlink_packet_utils::{
    buffer,
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const MONITOR_MIGRATE_HEADER_LEN: usize = XFRM_USER_POLICY_ID_LEN;

buffer!(MigrateMessageBuffer(MONITOR_MIGRATE_HEADER_LEN) {
    user_policy_id: (slice, 0..MONITOR_MIGRATE_HEADER_LEN),
    attributes: (slice, MONITOR_MIGRATE_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> MigrateMessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
