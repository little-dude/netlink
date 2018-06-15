mod flags;
pub use self::flags::*;
mod link_layer_type;
pub use self::link_layer_type::*;

use super::{LinkBuffer, HEADER_LEN};
use {Emitable, Parseable, Result};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkHeader {
    pub address_family: u8,
    pub link_layer_type: LinkLayerType,
    pub flags: LinkFlags,
}

impl Emitable for LinkHeader {
    fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = LinkBuffer::new(buffer);
        packet.set_address_family(self.address_family);
        packet.set_link_layer_type(self.link_layer_type);
        packet.set_flags(self.flags);
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkHeader> for LinkBuffer<T> {
    fn parse(&self) -> Result<LinkHeader> {
        Ok(LinkHeader {
            address_family: self.address_family(),
            link_layer_type: self.link_layer_type(),
            flags: self.flags(),
        })
    }
}
