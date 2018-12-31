use std::convert::TryFrom;

use byteorder::{ByteOrder, NativeEndian};

use crate::constants::*;
use crate::DecodeError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleSyscalls(pub(crate) Vec<u32>);

const BITMASK_BYTES_LEN: usize = AUDIT_BITMASK_SIZE * 4;

impl<'a> TryFrom<&'a [u8]> for RuleSyscalls {
    type Error = DecodeError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != BITMASK_BYTES_LEN {
            return Err(DecodeError::from(format!(
                "invalid bitmask size: expected {} bytes got {}",
                BITMASK_BYTES_LEN,
                slice.len()
            )));
        }
        let mut mask = RuleSyscalls::new_zeroed();
        let mut word = 0;
        while word < AUDIT_BITMASK_SIZE {
            mask.0[word] = NativeEndian::read_u32(&slice[word * 4..word * 4 + 4]);
            word += 1;
        }
        Ok(mask)
    }
}

// FIXME: I'm not 100% sure this implementation is correct wrt to endianness.
impl RuleSyscalls {
    pub fn new_zeroed() -> Self {
        RuleSyscalls(vec![0; AUDIT_BITMASK_SIZE])
    }

    pub fn new_maxed() -> Self {
        RuleSyscalls(vec![0xffff_ffff; AUDIT_BITMASK_SIZE])
    }

    /// Unset all the bits
    pub fn unset_all(&mut self) -> &mut Self {
        self.0 = vec![0; AUDIT_BITMASK_SIZE];
        self
    }

    /// Set all the bits
    pub fn set_all(&mut self) -> &mut Self {
        self.0 = vec![0xffff_ffff; AUDIT_BITMASK_SIZE];
        self
    }

    /// Unset the bit corresponding to the given syscall
    pub fn unset(&mut self, syscall: u32) -> &mut Self {
        let word = (syscall as usize) / 32;
        self.0[word] &= !(0x0000_0001 << (syscall as usize - word * 32));
        self
    }

    /// Set the bit corresponding to the given syscall
    pub fn set(&mut self, syscall: usize) -> &mut Self {
        let word = syscall as usize / 32;
        self.0[word] |= 0x0000_0001 << (syscall as usize - word * 32);
        self
    }

    /// Check if the bit corresponding to the given syscall is set
    pub fn has(&self, syscall: usize) -> bool {
        let word = syscall as usize / 32;
        (self.0[word] >> (syscall as usize - word * 32)) == 1
    }
}
