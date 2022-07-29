// SPDX-License-Identifier: MIT

use core::ops::Range;

use netlink_packet_utils::{
    buffer,
    traits::*,
    DecodeError,
};

pub const XFRM_ALG_AEAD_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgAead {
    pub alg_name: [u8; XFRM_ALG_AEAD_NAME_LEN],
    pub alg_key_len: u32,
    pub alg_icv_len: u32,
    pub alg_key: Vec<u8>
}

const ALG_NAME_FIELD: Range<usize>    = 0..XFRM_ALG_AEAD_NAME_LEN;
const ALG_KEY_LEN_FIELD: Range<usize> = ALG_NAME_FIELD.end..(ALG_NAME_FIELD.end + 4);
const ALG_ICV_LEN_FIELD: Range<usize> = ALG_KEY_LEN_FIELD.end..(ALG_KEY_LEN_FIELD.end + 4);

pub const XFRM_ALG_AEAD_HEADER_LEN: usize = XFRM_ALG_AEAD_NAME_LEN + 4 + 4;

buffer!(AlgAeadBuffer(XFRM_ALG_AEAD_HEADER_LEN) {
    alg_name: (slice, ALG_NAME_FIELD),
    alg_key_len: (u32, ALG_KEY_LEN_FIELD),
    alg_icv_len: (u32, ALG_ICV_LEN_FIELD),
    alg_key: (slice, ALG_ICV_LEN_FIELD.end..)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<AlgAeadBuffer<&T>> for AlgAead {
    fn parse(buf: &AlgAeadBuffer<&T>) -> Result<Self, DecodeError> {
        let mut alg_name: [u8; XFRM_ALG_AEAD_NAME_LEN] = [0; XFRM_ALG_AEAD_NAME_LEN];
        alg_name.clone_from_slice(&buf.alg_name());

        Ok(AlgAead {
            alg_name,
            alg_key_len: buf.alg_key_len(),
            alg_icv_len: buf.alg_icv_len(),
            alg_key: buf.alg_key().to_vec()
        })
    }
}

impl Emitable for AlgAead {
    fn buffer_len(&self) -> usize {
        XFRM_ALG_AEAD_HEADER_LEN + self.alg_key.len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = AlgAeadBuffer::new(buffer);
        buffer.alg_name_mut().clone_from_slice(&self.alg_name[..]);
        buffer.set_alg_key_len(self.alg_key_len);
        buffer.set_alg_icv_len(self.alg_icv_len);
        buffer.alg_key_mut().clone_from_slice(&self.alg_key[..]);
    }
}
