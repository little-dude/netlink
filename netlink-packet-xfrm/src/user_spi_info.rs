// SPDX-License-Identifier: MIT

use anyhow::Context;

use core::ops::Range;

use crate::{UserSaInfo, UserSaInfoBuffer, XFRM_USER_SA_INFO_LEN};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserSpiInfo {
    pub info: UserSaInfo,
    pub min: u32,
    pub max: u32,
}

const INFO_FIELD: Range<usize> = 0..XFRM_USER_SA_INFO_LEN;
const MIN_FIELD: Range<usize> = INFO_FIELD.end..(INFO_FIELD.end + 4);
const MAX_FIELD: Range<usize> = MIN_FIELD.end..(MIN_FIELD.end + 4);

pub const XFRM_USER_SPI_INFO_LEN: usize = (MAX_FIELD.end + 7) & !7; // 232

buffer!(UserSpiInfoBuffer(XFRM_USER_SPI_INFO_LEN) {
    info: (slice, INFO_FIELD),
    min: (u32, MIN_FIELD),
    max: (u32, MAX_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserSpiInfoBuffer<&T>> for UserSpiInfo {
    fn parse(buf: &UserSpiInfoBuffer<&T>) -> Result<Self, DecodeError> {
        let info = UserSaInfo::parse(&UserSaInfoBuffer::new(&buf.info()))
            .context("failed to parse user sa info")?;
        Ok(UserSpiInfo {
            info,
            min: buf.min(),
            max: buf.max(),
        })
    }
}

impl Emitable for UserSpiInfo {
    fn buffer_len(&self) -> usize {
        XFRM_USER_SPI_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserSpiInfoBuffer::new(buffer);
        self.info.emit(buffer.info_mut());
        buffer.set_min(self.min);
        buffer.set_max(self.max);
    }
}
