use super::{field, Error, Repr, Result};
use byteorder::{ByteOrder, NativeEndian};

const LENGTH: field::Field = 0..2;
const TYPE: field::Field = 2..4;
#[allow(non_snake_case)]
fn VALUE(length: usize) -> field::Field {
    field::dynamic_field(TYPE.end, length)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new(buffer);
        packet.check_buffer_length()?;
        Ok(packet)
    }

    pub fn check_buffer_length(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < TYPE.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the `type` field
    pub fn kind(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[TYPE])
    }

    /// Return the `length` field. The `length` field corresponds to the length of the attribute
    /// header (type and length fields, and the value field). However, it does not account for the
    /// potential padding that follows the value field.
    pub fn length(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[LENGTH])
    }

    /// Return the length of the `value` field
    pub fn value_length(&self) -> Result<usize> {
        let total_length = self.length() as usize;
        let value_offset = TYPE.end;
        if total_length < value_offset {
            return Err(Error::Malformed);
        }
        Ok(total_length - value_offset)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the `type` field
    pub fn set_kind(&mut self, kind: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[TYPE], kind)
    }

    /// Set the `length` field
    pub fn set_length(&mut self, length: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[LENGTH], length)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return the `value` field
    pub fn value(&self) -> Result<&[u8]> {
        Ok(&self.buffer.as_ref()[VALUE(self.value_length()?)])
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return the `value` field
    pub fn value_mut(&mut self) -> Result<&mut [u8]> {
        let length = VALUE(self.value_length()?);
        Ok(&mut self.buffer.as_mut()[length])
    }
}

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
    fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
    fn from_packet<'a, T: AsRef<[u8]> + ?Sized>(packet: Packet<&'a T>) -> Result<Self> {
        Ok(DefaultAttribute {
            kind: packet.kind(),
            value: packet.value()?.to_vec(),
        })
    }
}

pub trait Attribute: Sized {
    fn length(&self) -> usize;
    fn kind(&self) -> u16;
    fn value(&self) -> &[u8];
    fn from_packet<'a, T: AsRef<[u8]> + ?Sized>(packet: Packet<&'a T>) -> Result<Self>;
}

impl<T> Repr for T
where
    T: Attribute,
{
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        T::from_packet(packet)
    }

    fn buffer_len(&self) -> usize {
        self.length() as usize
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() < self.buffer_len() {
            return Err(Error::Exhausted);
        }
        let mut packet = Packet::new(buffer);
        packet.set_kind(self.kind());
        packet.set_length(self.length() as u16 + 4);
        packet.value_mut()?.copy_from_slice(self.value());
        Ok(())
    }
}

pub fn emit_attributes<T, U>(attributes: T)
where
    T: Iterator<Item = U>,
    U: Attribute,
{
    unimplemented!()
}

/// An iterator that iteratates over attributes without decoding them. This is useful when looking
/// for specific attributes.
pub struct AttributesIterator<'a> {
    position: usize,
    buffer: &'a [u8],
}

impl<'a> Iterator for AttributesIterator<'a> {
    type Item = Result<Packet<&'a [u8]>>;

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

        match Packet::new_checked(&self.buffer[self.position..]) {
            Ok(packet) => {
                self.position += packet.length() as usize;
                return Some(Ok(packet));
            }
            Err(e) => {
                // Make sure next time we call `next()`, we return None. We don't try to continue
                // iterating after we failed to return a packet.
                self.position = self.buffer.len();
                return Some(Err(e));
            }
        }
    }
}
