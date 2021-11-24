// SPDX-License-Identifier: MIT

use crate::{
    message::{NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NETFILTER_HEADER_LEN},
    nflog::NfLogMessage,
    traits::{Parseable, ParseableParametrized},
    DecodeError,
};
use anyhow::Context;
use netlink_packet_utils::{
    buffer,
    nla::{DefaultNla, NlaBuffer, NlasIterator},
};

buffer!(NetfilterBuffer(NETFILTER_HEADER_LEN) {
    header: (slice, ..NETFILTER_HEADER_LEN),
    payload: (slice, NETFILTER_HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized> NetfilterBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }

    pub fn parse_all_nlas<F, U>(&self, f: F) -> Result<Vec<U>, DecodeError>
    where
        F: Fn(NlaBuffer<&[u8]>) -> Result<U, DecodeError>,
    {
        Ok(self
            .nlas()
            .map(|buf| f(buf?))
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse NLAs")?)
    }

    pub fn default_nlas(&self) -> Result<Vec<DefaultNla>, DecodeError> {
        self.parse_all_nlas(|buf| DefaultNla::parse(&buf))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<NetfilterBuffer<&'a T>, u16>
    for NetfilterMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        let header_buf = crate::message::NetfilterHeaderBuffer::new(buf.inner());
        let header =
            NetfilterHeader::parse(&header_buf).context("failed to parse netfilter header")?;
        let subsys = (message_type >> 8) as u8;
        let message_type = message_type as u8;
        let inner = match subsys {
            NfLogMessage::SUBSYS => {
                NetfilterMessageInner::NfLog(NfLogMessage::parse_with_param(buf, message_type)?)
            }
            _ => NetfilterMessageInner::Other {
                subsys,
                message_type,
                nlas: buf.default_nlas()?,
            },
        };
        Ok(NetfilterMessage::new(header, inner))
    }
}
