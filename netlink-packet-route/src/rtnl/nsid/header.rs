use super::{NsIdBuffer, NSID_HEADER_LEN};
use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NsIdHeader {
    pub rtgen_family: u8,
}

impl Default for NsIdHeader {
    fn default() -> Self {
        NsIdHeader::new()
    }
}

impl NsIdHeader {
    /// Create a new `NsIdHeader`:
    pub fn new() -> Self {
        NsIdHeader { rtgen_family: 0 }
    }
}

impl Emitable for NsIdHeader {
    fn buffer_len(&self) -> usize {
        NSID_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = NsIdBuffer::new(buffer);
        packet.set_rtgen_family(self.rtgen_family);
    }
}

impl<T: AsRef<[u8]>> Parseable<NsIdHeader> for NsIdBuffer<T> {
    fn parse(&self) -> Result<NsIdHeader, DecodeError> {
        Ok(NsIdHeader {
            rtgen_family: self.rtgen_family(),
        })
    }
}
