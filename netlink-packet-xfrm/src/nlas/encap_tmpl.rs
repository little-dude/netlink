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
pub struct EncapTmpl {
    pub encap_type: u16,
    pub encap_sport: u16, // big-endian
    pub encap_dport: u16, // big-endian
    pub encap_oa: Address
}

const TYPE_FIELD: Range<usize>  = 0..2;
const SPORT_FIELD: Range<usize> = TYPE_FIELD.end..(TYPE_FIELD.end + 2);
const DPORT_FIELD: Range<usize> = SPORT_FIELD.end..(SPORT_FIELD.end + 2);
const OA_FIELD: Range<usize>    = (DPORT_FIELD.end + 2)..(DPORT_FIELD.end + 2 + XFRM_ADDRESS_LEN);

pub const XFRM_ENCAP_TMPL_LEN: usize = OA_FIELD.end; // 24

buffer!(EncapTmplBuffer(XFRM_ENCAP_TMPL_LEN) {
    encap_type: (u16, TYPE_FIELD),
    encap_sport: (u16, SPORT_FIELD),
    encap_dport: (u16, DPORT_FIELD),
    /* 2 bytes padding */
    encap_oa: (slice, OA_FIELD)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<EncapTmplBuffer<&T>> for EncapTmpl {
    fn parse(buf: &EncapTmplBuffer<&T>) -> Result<Self, DecodeError> {
        let encap_oa = Address::parse(&AddressBuffer::new(&buf.encap_oa()))
            .context("failed to parse oa address")?;
        Ok(EncapTmpl {
            encap_type: buf.encap_type(),
            encap_sport: u16::from_be(buf.encap_sport()),
            encap_dport: u16::from_be(buf.encap_dport()),
            encap_oa
        })
    }
}

impl Emitable for EncapTmpl {
    fn buffer_len(&self) -> usize {
        XFRM_ENCAP_TMPL_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = EncapTmplBuffer::new(buffer);
        buffer.set_encap_type(self.encap_type);
        buffer.set_encap_sport(self.encap_sport.to_be());
        buffer.set_encap_dport(self.encap_dport.to_be());
        self.encap_oa.emit(buffer.encap_oa_mut());
    }
}
