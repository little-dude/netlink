use super::{field, Error, Repr, Result};
use byteorder::{ByteOrder, NativeEndian};
use constants;
use std::mem::size_of;
use std::ptr;

const TYPE_MASK: u16 = (constants::NLA_TYPE_MASK & 0xFFFF) as u16;
const NESTED_MASK: u16 = (constants::NLA_F_NESTED & 0xFFFF) as u16;
const NET_BYTEORDER_MASK: u16 = (constants::NLA_F_NET_BYTEORDER & 0xFFFF) as u16;

const LENGTH: field::Field = 0..2;
const TYPE: field::Field = 2..4;

#[allow(non_snake_case)]
fn VALUE(length: usize) -> field::Field {
    field::dynamic_field(TYPE.end, length)
}

// with Copy, Buffer<&'a T> can be copied, which turns out to be pretty conveninent. And since it's
// boils down to copying a reference it's pretty cheap
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Buffer<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Buffer<T> {
    pub fn new(buffer: T) -> Buffer<T> {
        Buffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Buffer<T>> {
        let buffer = Self::new(buffer);
        buffer.check_buffer_length()?;
        Ok(buffer)
    }

    pub fn check_buffer_length(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < TYPE.end {
            Err(Error::Truncated)
        } else if (self.length() as usize) < TYPE.end {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }

    /// Consume the buffer, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the `type` field
    pub fn kind(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[TYPE]) & TYPE_MASK
    }

    pub fn nested_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (NativeEndian::read_u16(&data[TYPE]) & NESTED_MASK) != 0
    }

    pub fn network_byte_order_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (NativeEndian::read_u16(&data[TYPE]) & NET_BYTEORDER_MASK) != 0
    }

    /// Return the `length` field. The `length` field corresponds to the length of the attribute
    /// header (type and length fields, and the value field). However, it does not account for the
    /// potential padding that follows the value field.
    pub fn length(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[LENGTH])
    }

    /// Return the length of the `value` field
    ///
    /// # Panic
    ///
    /// This panics if the length field value is less than the attribut header size.
    pub fn value_length(&self) -> usize {
        self.length() as usize - TYPE.end
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Buffer<T> {
    /// Set the `type` field
    pub fn set_kind(&mut self, kind: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[TYPE], kind & TYPE_MASK)
    }

    pub fn set_nested_flag(&mut self) {
        let kind = self.kind();
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[TYPE], kind | NESTED_MASK)
    }

    pub fn set_network_byte_order_flag(&mut self) {
        let kind = self.kind();
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[TYPE], kind | NET_BYTEORDER_MASK)
    }

    /// Set the `length` field
    pub fn set_length(&mut self, length: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[LENGTH], length)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Buffer<&'a T> {
    /// Return the `value` field
    pub fn value(&self) -> &[u8] {
        &self.buffer.as_ref()[VALUE(self.value_length())]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Buffer<&'a mut T> {
    /// Return the `value` field
    pub fn value_mut(&mut self) -> &mut [u8] {
        let length = VALUE(self.value_length());
        &mut self.buffer.as_mut()[length]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DefaultAttribute {
    kind: u16,
    value: Vec<u8>,
}

impl Attribute for DefaultAttribute {
    fn length(&self) -> usize {
        self.value.len()
    }
    fn kind(&self) -> u16 {
        self.kind
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self.value.as_slice());
    }
    fn parse<'a, T: AsRef<[u8]> + ?Sized>(buffer: Buffer<&'a T>) -> Result<Self> {
        buffer.check_buffer_length()?;
        Ok(DefaultAttribute {
            kind: buffer.kind(),
            value: buffer.value().to_vec(),
        })
    }
}

pub trait Attribute: Sized {
    fn length(&self) -> usize;
    fn kind(&self) -> u16;
    fn emit_value(&self, buffer: &mut [u8]);
    fn parse<'a, T: AsRef<[u8]> + ?Sized>(buffer: Buffer<&'a T>) -> Result<Self>;
}

impl<T> Repr for T
where
    T: Attribute,
{
    fn parse(buffer: &[u8]) -> Result<Self> {
        let buffer = Buffer::new_checked(buffer)?;
        T::parse(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.length() as usize + 4
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        let mut buffer = Buffer::new(buffer);
        buffer.set_kind(self.kind());
        buffer.set_length(self.buffer_len() as u16);
        self.emit_value(buffer.value_mut());
        Ok(())
    }
}

/// # Panic
///
/// If an attribute emits a malformed buffer this method will panic.
pub fn emit_attributes<'a, T, U>(buffer: &mut [u8], attributes: T) -> Result<usize>
where
    T: Iterator<Item = &'a U>,
    U: Attribute + 'a,
{
    // FIXME: can this be optimized? The gymnastic with the start and end indices seems
    // inefficient.
    let mut start = 0;
    let mut end: usize;
    for attribute in attributes {
        let attr_len = attribute.buffer_len();
        if (buffer.len() - start) < attr_len {
            return Err(Error::Exhausted);
        }
        end = start + attr_len;
        attribute.emit(&mut buffer[start..end])?;
        start = end;
    }
    Ok(start)
}

// FIXME: should we make the buffer attribute a generic T: AsRef<[u8]> instead?
//
// FIXME (?): currently, each buffer we return has an underlying buffer that is longer than
// necessary. This is not really a problem, but it might be confusing for users calling
// `into_inner` on these buffers, because they'll get a slice that is longer than expected.

/// An iterator that iteratates over attributes without decoding them. This is useful when looking
/// for specific attributes.
pub struct AttributesIterator<'a> {
    position: usize,
    buffer: &'a [u8],
}

impl<'a> AttributesIterator<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        AttributesIterator {
            position: 0,
            buffer,
        }
    }
}

impl<'a> Iterator for AttributesIterator<'a> {
    type Item = Result<Buffer<&'a [u8]>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Attributes are aligned on 4 bytes boundaries, so we make sure we ignore any potential
        // padding.
        let offset = self.position % 4;
        if offset != 0 {
            self.position += 4 - offset;
        }

        if self.position >= self.buffer.len() {
            return None;
        }

        match Buffer::new_checked(&self.buffer[self.position..]) {
            Ok(buffer) => {
                self.position += buffer.length() as usize;
                Some(Ok(buffer))
            }
            Err(e) => {
                // Make sure next time we call `next()`, we return None. We don't try to continue
                // iterating after we failed to return a buffer.
                self.position = self.buffer.len();
                Some(Err(e))
            }
        }
    }
}

pub fn parse_mac(payload: &[u8]) -> Result<[u8; 6]> {
    if payload.len() != 6 {
        return Err(Error::MalformedAttributeValue);
    }
    let mut address: [u8; 6] = [0; 6];
    for (i, byte) in payload.into_iter().enumerate() {
        address[i] = *byte;
    }
    Ok(address)
}

pub fn parse_ipv6(payload: &[u8]) -> Result<[u8; 16]> {
    if payload.len() != 16 {
        return Err(Error::MalformedAttributeValue);
    }
    let mut address: [u8; 16] = [0; 16];
    for (i, byte) in payload.into_iter().enumerate() {
        address[i] = *byte;
    }
    Ok(address)
}

pub fn parse_string(payload: &[u8]) -> Result<String> {
    if payload.is_empty() {
        return Ok(String::new());
    }
    let s = String::from_utf8(payload[..payload.len() - 1].to_vec())
        .map_err(|_| Error::MalformedAttributeValue)?;
    Ok(s)
}

pub fn parse_u8(payload: &[u8]) -> Result<u8> {
    if payload.len() != 1 {
        return Err(Error::MalformedAttributeValue);
    }
    Ok(payload[0])
}

pub fn parse_u32(payload: &[u8]) -> Result<u32> {
    if payload.len() != 4 {
        return Err(Error::MalformedAttributeValue);
    }
    Ok(NativeEndian::read_u32(payload))
}

pub fn parse_i32(payload: &[u8]) -> Result<i32> {
    if payload.len() != 4 {
        return Err(Error::MalformedAttributeValue);
    }
    Ok(NativeEndian::read_i32(payload))
}

pub trait NativeAttribute
where
    Self: Sized + Copy,
{
    fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != size_of::<Self>() {
            return Err(Error::MalformedAttributeValue);
        }
        Ok(unsafe { ptr::read(buf.as_ptr() as *const Self) })
    }

    fn to_bytes(&self, buf: &mut [u8]) {
        unsafe { ptr::write(buf.as_mut_ptr() as *mut Self, *self) }
    }
}
