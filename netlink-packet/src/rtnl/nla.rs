use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::constants::{NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLA_TYPE_MASK};
use crate::{DecodeError, Emitable, Field, Parseable};

const LENGTH: Field = 0..2;
const TYPE: Field = 2..4;
#[allow(non_snake_case)]
fn VALUE(length: usize) -> Field {
    TYPE.end..TYPE.end + length
}

// with Copy, NlaBuffer<&'buffer T> can be copied, which turns out to be pretty conveninent. And since it's
// boils down to copying a reference it's pretty cheap
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NlaBuffer<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NlaBuffer<T> {
    pub fn new(buffer: T) -> NlaBuffer<T> {
        NlaBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<NlaBuffer<T>, DecodeError> {
        let buffer = Self::new(buffer);
        buffer.check_buffer_length().context("invalid NLA buffer")?;
        Ok(buffer)
    }

    pub fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < TYPE.end {
            Err(format!(
                "buffer has length {}, but an NLA header is {} bytes",
                len, TYPE.end
            )
            .into())
        } else if len < self.length() as usize {
            Err(format!(
                "buffer has length: {}, but the NLA is {} bytes",
                len,
                self.length()
            )
            .into())
        } else if (self.length() as usize) < TYPE.end {
            Err(format!(
                "NLA has invalid length: {} (should be at least {} bytes",
                self.length(),
                TYPE.end,
            )
            .into())
        } else {
            Ok(())
        }
    }

    /// Consume the buffer, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    fn as_mut(&mut self) -> &mut T {
        &mut self.buffer
    }

    /// Return the `type` field
    pub fn kind(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[TYPE]) & NLA_TYPE_MASK
    }

    pub fn nested_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (NativeEndian::read_u16(&data[TYPE]) & NLA_F_NESTED) != 0
    }

    pub fn network_byte_order_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (NativeEndian::read_u16(&data[TYPE]) & NLA_F_NET_BYTEORDER) != 0
    }

    /// Return the `length` field. The `length` field corresponds to the length of the nla
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

impl<T: AsRef<[u8]> + AsMut<[u8]>> NlaBuffer<T> {
    /// Set the `type` field
    pub fn set_kind(&mut self, kind: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[TYPE], kind & NLA_TYPE_MASK)
    }

    pub fn set_nested_flag(&mut self) {
        let kind = self.kind();
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[TYPE], kind | NLA_F_NESTED)
    }

    pub fn set_network_byte_order_flag(&mut self) {
        let kind = self.kind();
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[TYPE], kind | NLA_F_NET_BYTEORDER)
    }

    /// Set the `length` field
    pub fn set_length(&mut self, length: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[LENGTH], length)
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> NlaBuffer<&'buffer T> {
    /// Return the `value` field
    pub fn value(&self) -> &[u8] {
        &self.buffer.as_ref()[VALUE(self.value_length())]
    }
}

impl<'buffer, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NlaBuffer<&'buffer mut T> {
    /// Return the `value` field
    pub fn value_mut(&mut self) -> &mut [u8] {
        let length = VALUE(self.value_length());
        &mut self.buffer.as_mut()[length]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DefaultNla {
    kind: u16,
    value: Vec<u8>,
}

impl Nla for DefaultNla {
    fn value_len(&self) -> usize {
        self.value.len()
    }
    fn kind(&self) -> u16 {
        self.kind
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self.value.as_slice());
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<DefaultNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<DefaultNla, DecodeError> {
        Ok(DefaultNla {
            kind: self.kind(),
            value: self.value().to_vec(),
        })
    }
}

pub trait Nla {
    fn value_len(&self) -> usize;

    fn kind(&self) -> u16;

    fn emit_value(&self, buffer: &mut [u8]);
}

impl<T: Nla> Emitable for T {
    fn buffer_len(&self) -> usize {
        let padding = (4 - self.value_len() % 4) % 4;
        self.value_len() + padding + 4
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NlaBuffer::new(buffer);
        buffer.set_kind(self.kind());
        // do not include the padding here, but do include the header
        buffer.set_length(self.value_len() as u16 + 4);
        self.emit_value(buffer.value_mut());
        // add the padding. this is a bit ugly, not sure how to make it better
        let padding = (4 - self.value_len() % 4) % 4;
        for i in 0..padding {
            buffer.as_mut()[4 + self.value_len() + i] = 0;
        }
    }
}

impl<'a, T: Nla> Emitable for &'a [T] {
    fn buffer_len(&self) -> usize {
        self.iter().fold(0, |acc, nla| {
            assert_eq!(nla.buffer_len() % 4, 0);
            acc + nla.buffer_len()
        })
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut start = 0;
        let mut end: usize;
        for nla in self.iter() {
            let attr_len = nla.buffer_len();
            assert_eq!(nla.buffer_len() % 4, 0);
            end = start + attr_len;
            nla.emit(&mut buffer[start..end]);
            start = end;
        }
    }
}

/// An iterator that iteratates over nlas without decoding them. This is useful when looking
/// for specific nlas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlasIterator<T> {
    position: usize,
    buffer: T,
}

impl<T> NlasIterator<T> {
    pub fn new(buffer: T) -> Self {
        NlasIterator {
            position: 0,
            buffer,
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized + 'buffer> Iterator for NlasIterator<&'buffer T> {
    type Item = Result<NlaBuffer<&'buffer [u8]>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Nlas are aligned on 4 bytes boundaries, so we make sure we ignore any potential
        // padding.
        let offset = self.position % 4;
        if offset != 0 {
            self.position += 4 - offset;
        }

        if self.position >= self.buffer.as_ref().len() {
            return None;
        }

        match NlaBuffer::new_checked(&self.buffer.as_ref()[self.position..]) {
            Ok(nla_buffer) => {
                self.position += nla_buffer.length() as usize;
                Some(Ok(nla_buffer))
            }
            Err(e) => {
                // Make sure next time we call `next()`, we return None. We don't try to continue
                // iterating after we failed to return a buffer.
                self.position = self.buffer.as_ref().len();
                Some(Err(e))
            }
        }
    }
}
