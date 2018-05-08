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

    /// Return the `length` field
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

/// Represent an attribute
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Attribute {
    Other { kind: u16, value: Vec<u8> },
}

impl Repr for Attribute {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        Ok(match packet.kind() {
            other => Attribute::Other {
                kind: other,
                value: packet.value()?.to_vec(),
            },
        })
    }

    fn buffer_len(&self) -> usize {
        use self::Attribute::*;
        let value_len = match *self {
            Other { ref value, .. } => value.len(),
        };
        value_len + 4
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        use self::Attribute::*;
        if buffer.len() < self.buffer_len() {
            return Err(Error::Exhausted);
        }
        let mut packet = Packet::new(buffer);
        match *self {
            Other {
                ref kind,
                ref value,
            } => {
                packet.set_kind(*kind);
                packet.set_length(value.len() as u16 + 4);
                packet.value_mut()?.copy_from_slice(value.as_slice());
            }
        }
        Ok(())
    }
}
