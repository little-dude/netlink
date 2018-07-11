use super::header::*;
use byteorder::{ByteOrder, NativeEndian};
use {Field, Index, NlaBuffer, NlasIterator, Rest, Result};

const ADDRESS_FAMILY: Index = 0;
const DEST_LENGTH: Index = 1;
const SOURCE_LENGTH: Index = 2;
const TOS: Index = 3;
const TABLE_ID: Index = 4;
const ROUTING_PROTOCOL: Index = 5;
const SCOPE: Index = 6;
const TYPE: Index = 7;
const FLAGS: Field = 8..12;
const ATTRIBUTES: Rest = 12..;

pub const ROUTE_HEADER_LEN: usize = ATTRIBUTES.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RouteBuffer<T> {
    pub fn new(buffer: T) -> RouteBuffer<T> {
        RouteBuffer { buffer }
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

    /// Return the destination length field
    pub fn destination_length(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[DEST_LENGTH]
    }

    /// Return the source length field
    pub fn source_length(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SOURCE_LENGTH]
    }

    /// Return the tos field
    pub fn tos(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[TOS]
    }

    /// Return the table id field
    pub fn table(&self) -> RouteTable {
        let data = self.buffer.as_ref();
        data[TABLE_ID].into()
    }

    /// Return the routing protocol field
    pub fn protocol(&self) -> RouteProtocol {
        let data = self.buffer.as_ref();
        data[ROUTING_PROTOCOL].into()
    }

    /// Return the scope field
    pub fn scope(&self) -> RouteScope {
        let data = self.buffer.as_ref();
        data[SCOPE].into()
    }

    /// Return the routie type field
    pub fn kind(&self) -> RouteKind {
        let data = self.buffer.as_ref();
        data[TYPE].into()
    }

    /// Return the flags field
    pub fn flags(&self) -> RouteFlags {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[FLAGS]).into()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> RouteBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> RouteBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RouteBuffer<T> {
    /// Set the address family field
    pub fn set_address_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[ADDRESS_FAMILY] = value
    }

    /// Set the destination length field
    pub fn set_destination_length(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[DEST_LENGTH] = value
    }

    /// Set the source length field
    pub fn set_source_length(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[SOURCE_LENGTH] = value
    }

    /// Set the tos field
    pub fn set_tos(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[TOS] = value
    }

    /// Set the table id field
    pub fn set_table(&mut self, value: RouteTable) {
        let data = self.buffer.as_mut();
        data[TABLE_ID] = value.into()
    }

    /// Set the routing protocol field
    pub fn set_protocol(&mut self, value: RouteProtocol) {
        let data = self.buffer.as_mut();
        data[ROUTING_PROTOCOL] = value.into()
    }

    /// Set the scope field
    pub fn set_scope(&mut self, value: RouteScope) {
        let data = self.buffer.as_mut();
        data[SCOPE] = value.into()
    }

    /// Set the routie type field
    pub fn set_kind(&mut self, value: RouteKind) {
        let data = self.buffer.as_mut();
        data[TYPE] = value.into()
    }

    /// Set the flags field
    pub fn set_flags(&mut self, value: RouteFlags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[FLAGS], value.into())
    }
}
