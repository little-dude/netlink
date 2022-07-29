// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    buffer,
    traits::*,
    DecodeError,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecurityCtx {
    pub len: u16,
    pub exttype: u16,
    pub ctx_alg: u8,
    pub ctx_doi: u8,
    pub ctx_len: u16,
    pub ctx_str: Vec<u8>
}

pub const XFRM_SEC_CTX_HEADER_LEN: usize = 8;

buffer!(SecurityCtxBuffer(XFRM_SEC_CTX_HEADER_LEN) {
    len: (u16, 0..2),
    exttype: (u16, 2..4),
    ctx_alg: (u8, 4),
    ctx_doi: (u8, 5),
    ctx_len: (u16, 6..8),
    ctx_str: (slice, 8..)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<SecurityCtxBuffer<&T>> for SecurityCtx {
    fn parse(buf: &SecurityCtxBuffer<&T>) -> Result<Self, DecodeError> {
        Ok(SecurityCtx {
            len: buf.len(),
            exttype: buf.exttype(),
            ctx_alg: buf.ctx_alg(),
            ctx_doi: buf.ctx_doi(),
            ctx_len: buf.ctx_len(),
            ctx_str: buf.ctx_str().to_vec()
        })
    }
}

impl Emitable for SecurityCtx {
    fn buffer_len(&self) -> usize {
        XFRM_SEC_CTX_HEADER_LEN + self.ctx_str.len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = SecurityCtxBuffer::new(buffer);
        buffer.set_len(self.len);
        buffer.set_exttype(self.exttype);
        buffer.set_ctx_alg(self.ctx_alg);
        buffer.set_ctx_doi(self.ctx_doi);
        buffer.set_ctx_len(self.ctx_len);
        buffer.ctx_str_mut().clone_from_slice(&self.ctx_str[..]);
    }
}
