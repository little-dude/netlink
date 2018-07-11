use byteorder::{ByteOrder, NativeEndian};
use {Field, Index, NlaBuffer, NlasIterator, Rest, Result};

use super::{LinkFlags, LinkLayerType};

const ADDRESS_FAMILY: Index = 0;
const RESERVED_1: Index = 1;
const LINK_LAYER_TYPE: Field = 2..4;
const LINK_INDEX: Field = 4..8;
const FLAGS: Field = 8..12;
const CHANGE_MASK: Field = 12..16;
const ATTRIBUTES: Rest = 16..;

pub const LINK_HEADER_LEN: usize = ATTRIBUTES.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkBuffer<T> {
    pub fn new(buffer: T) -> LinkBuffer<T> {
        LinkBuffer { buffer }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the address family field
    pub fn address_family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[ADDRESS_FAMILY]
    }

    /// Return the link layer type field
    pub fn reserved_1(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[RESERVED_1]
    }

    /// Return the link layer type field
    pub fn link_layer_type(&self) -> LinkLayerType {
        let data = self.buffer.as_ref();
        LinkLayerType::from(NativeEndian::read_u16(&data[LINK_LAYER_TYPE]))
    }

    /// Return the link index field
    pub fn link_index(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[LINK_INDEX])
    }

    /// Return the flags field
    pub fn flags(&self) -> LinkFlags {
        let data = self.buffer.as_ref();
        LinkFlags::from(NativeEndian::read_u32(&data[FLAGS]))
    }

    /// Return the link index field
    pub fn change_mask(&self) -> LinkFlags {
        let data = self.buffer.as_ref();
        LinkFlags::from(NativeEndian::read_u32(&data[CHANGE_MASK]))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> LinkBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> LinkBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkBuffer<T> {
    /// set the address family field
    pub fn set_address_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[ADDRESS_FAMILY] = value
    }

    pub fn set_reserved_1(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[RESERVED_1] = value
    }

    pub fn set_link_layer_type(&mut self, value: LinkLayerType) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[LINK_LAYER_TYPE], value.into())
    }

    pub fn set_link_index(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[LINK_INDEX], value)
    }

    pub fn set_flags(&mut self, value: LinkFlags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[FLAGS], value.into())
    }

    pub fn set_change_mask(&mut self, value: LinkFlags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[CHANGE_MASK], value.into())
    }
}
