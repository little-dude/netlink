mod flags;
pub use self::flags::*;
mod link_layer_type;
pub use self::link_layer_type::*;

use super::{LinkBuffer, HEADER_LEN};
use {Emitable, Parseable, Result};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkHeader {
    pub address_family: u8,
    pub index: u32,
    pub link_layer_type: LinkLayerType,
    pub flags: LinkFlags,
    pub change_mask: LinkFlags,
}

impl LinkHeader {
    pub fn address_family(&self) -> u8 {
        self.address_family
    }
    pub fn address_family_mut(&mut self) -> &mut u8 {
        &mut self.address_family
    }
    pub fn set_address_family(&mut self, value: u8) -> &mut Self {
        self.address_family = value;
        self
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn index_mut(&mut self) -> &mut u32 {
        &mut self.index
    }
    pub fn set_index(&mut self, value: u32) -> &mut Self {
        self.index = value;
        self
    }
    pub fn link_layer_type(&self) -> LinkLayerType {
        self.link_layer_type
    }
    pub fn link_layer_type_mut(&mut self) -> &mut LinkLayerType {
        &mut self.link_layer_type
    }
    pub fn set_link_layer_type(&mut self, value: LinkLayerType) -> &mut Self {
        self.link_layer_type = value;
        self
    }
    pub fn flags(&self) -> LinkFlags {
        self.flags
    }
    pub fn flags_mut(&mut self) -> &mut LinkFlags {
        &mut self.flags
    }
    pub fn set_flags(&mut self, value: LinkFlags) -> &mut Self {
        self.flags = value;
        self
    }
    pub fn change_mask(&self) -> LinkFlags {
        self.change_mask
    }
    pub fn change_mask_mut(&mut self) -> &mut LinkFlags {
        &mut self.change_mask
    }
    pub fn set_change_mask(&mut self, value: LinkFlags) -> &mut Self {
        self.change_mask = value;
        self
    }
}

impl Emitable for LinkHeader {
    fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = LinkBuffer::new(buffer);
        packet.set_address_family(self.address_family);
        packet.set_link_index(self.index);
        packet.set_change_mask(self.change_mask);
        packet.set_link_layer_type(self.link_layer_type);
        packet.set_flags(self.flags);
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkHeader> for LinkBuffer<T> {
    fn parse(&self) -> Result<LinkHeader> {
        Ok(LinkHeader {
            address_family: self.address_family(),
            link_layer_type: self.link_layer_type(),
            index: self.link_index(),
            change_mask: self.change_mask(),
            flags: self.flags(),
        })
    }
}
