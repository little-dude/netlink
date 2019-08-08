use byteorder::{ByteOrder, NativeEndian};

use crate::DecodeError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleSyscalls(pub(crate) Vec<u32>);

pub const AUDIT_MAX_FIELDS: usize = 64;
pub const AUDIT_MAX_KEY_LEN: usize = 256;
pub const AUDIT_BITMASK_SIZE: usize = 64;

const BITMASK_BYTE_LEN: usize = AUDIT_BITMASK_SIZE * 4;
const BITMASK_BIT_LEN: u32 = AUDIT_BITMASK_SIZE as u32 * 32;

// FIXME: I'm not 100% sure this implementation is correct wrt to endianness.
impl RuleSyscalls {
    // FIXME: this should be a TryFrom when it stabilized...
    pub fn from_slice(slice: &[u8]) -> Result<Self, DecodeError> {
        if slice.len() != BITMASK_BYTE_LEN {
            return Err(DecodeError::from(format!(
                "invalid bitmask size: expected {} bytes got {}",
                BITMASK_BYTE_LEN,
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

    /// Return `true` if all the syscalls are set, `false` otherwise
    pub fn is_all(&self) -> bool {
        for i in 0..AUDIT_BITMASK_SIZE {
            if self.0[i] != 0xffff_ffff {
                return false;
            }
        }
        true
    }

    /// Set all the bits
    pub fn set_all(&mut self) -> &mut Self {
        self.0 = vec![0xffff_ffff; AUDIT_BITMASK_SIZE];
        self
    }

    /// Unset the bit corresponding to the given syscall
    pub fn unset(&mut self, syscall: u32) -> &mut Self {
        let (word, mask) = Self::syscall_coordinates(syscall);
        self.0[word] &= !mask;
        self
    }

    /// Set the bit corresponding to the given syscall
    pub fn set(&mut self, syscall: u32) -> &mut Self {
        let (word, mask) = Self::syscall_coordinates(syscall);
        self.0[word] |= mask;
        self
    }

    /// Check if the bit corresponding to the given syscall is set
    pub fn has(&self, syscall: u32) -> bool {
        let (word, mask) = Self::syscall_coordinates(syscall);
        self.0[word] & mask == mask
    }

    fn syscall_coordinates(syscall: u32) -> (usize, u32) {
        let word_index = syscall / 32;
        let mask = 0x0000_0001 << (syscall - word_index * 32);
        (word_index as usize, mask)
    }
}

// FIXME: There is a LOT of copy paste for those iterator implementations... This feels wrong but I
// could not figure out how to avoid it :(

pub struct RuleSyscallsIter<T> {
    index: u32,
    syscalls: T,
}

impl IntoIterator for RuleSyscalls {
    type Item = u32;
    type IntoIter = RuleSyscallsIter<RuleSyscalls>;

    fn into_iter(self) -> Self::IntoIter {
        RuleSyscallsIter {
            index: 0,
            syscalls: self,
        }
    }
}

impl Iterator for RuleSyscallsIter<RuleSyscalls> {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        while self.index < BITMASK_BIT_LEN {
            let index = self.index;
            self.index += 1;
            if self.syscalls.has(index) {
                return Some(index as u32);
            }
        }
        None
    }
}

impl<'a> IntoIterator for &'a RuleSyscalls {
    type Item = u32;
    type IntoIter = RuleSyscallsIter<&'a RuleSyscalls>;

    fn into_iter(self) -> Self::IntoIter {
        RuleSyscallsIter {
            index: 0,
            syscalls: self,
        }
    }
}

impl<'a> Iterator for RuleSyscallsIter<&'a RuleSyscalls> {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        while self.index < BITMASK_BIT_LEN {
            let index = self.index;
            self.index += 1;
            if self.syscalls.has(index) {
                return Some(index as u32);
            }
        }
        None
    }
}

impl<'a> IntoIterator for &'a mut RuleSyscalls {
    type Item = u32;
    type IntoIter = RuleSyscallsIter<&'a mut RuleSyscalls>;

    fn into_iter(self) -> Self::IntoIter {
        RuleSyscallsIter {
            index: 0,
            syscalls: self,
        }
    }
}

impl<'a> Iterator for RuleSyscallsIter<&'a mut RuleSyscalls> {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        while self.index < BITMASK_BIT_LEN {
            let index = self.index;
            self.index += 1;
            if self.syscalls.has(index) {
                return Some(index as u32);
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_from_slice() {
        let s: Vec<u8> = vec![0xff; BITMASK_BYTE_LEN];
        let syscalls = RuleSyscalls::from_slice(&s[..]).unwrap();
        assert_eq!(syscalls.0, vec![0xffff_ffff; AUDIT_BITMASK_SIZE]);

        let s: Vec<u8> = vec![0; BITMASK_BYTE_LEN];
        let syscalls = RuleSyscalls::from_slice(&s[..]).unwrap();
        assert_eq!(syscalls.0, vec![0; AUDIT_BITMASK_SIZE]);
    }

    #[test]
    fn test_iter() {
        let s: Vec<u8> = vec![0xff; BITMASK_BYTE_LEN];
        let syscalls = RuleSyscalls::from_slice(&s[..]).unwrap();
        let mut iter = syscalls.into_iter();
        for i in 0..BITMASK_BIT_LEN {
            assert_eq!(i as u32, iter.next().unwrap());
        }
        assert!(iter.next().is_none());

        let s: Vec<u8> = vec![0; BITMASK_BYTE_LEN];
        let syscalls = RuleSyscalls::from_slice(&s[..]).unwrap();
        let mut iter = syscalls.into_iter();
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_set_unset() {
        let mut syscalls = RuleSyscalls::new_zeroed();
        for i in 0..BITMASK_BIT_LEN {
            syscalls.set(i);
        }
        assert_eq!(syscalls.0, vec![0xffff_ffff; AUDIT_BITMASK_SIZE]);
        for i in 0..BITMASK_BIT_LEN {
            syscalls.unset(BITMASK_BIT_LEN - 1 - i);
        }
        assert_eq!(syscalls.0, vec![0; AUDIT_BITMASK_SIZE]);
    }
}
