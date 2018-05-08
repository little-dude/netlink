use super::{field, Error, Flags, Repr, Result};
use byteorder::{ByteOrder, NativeEndian};

enum_with_other! {
    /// Field that describes the message content.
    pub doc enum MessageType(u16) {
        /// Message is ignored.
        Noop = 1,
        /// The message signals an error and the payload contains a nlmsgerr structure. This can be
        /// looked at as a NACK and typically it is from FEC to CPC.
        Error = 2,
        /// Message terminates a multipart message.
        Done = 3,
        /// Data lost
        Overrun = 4,
    }

}

const LENGTH: field::Field = 0..4;
const MESSAGE_TYPE: field::Field = 4..6;
const FLAGS: field::Field = 6..8;
const SEQUENCE_NUMBER: field::Field = 8..12;
const PORT_NUMBER: field::Field = 12..16;
const PAYLOAD: field::Rest = 16..;

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
        if len < PORT_NUMBER.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    pub fn payload_length(&self) -> Result<usize> {
        let total_length = self.length() as usize;
        let payload_offset = PAYLOAD.start;
        if total_length < payload_offset {
            return Err(Error::Malformed);
        }
        Ok(total_length - payload_offset)
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the `length` field
    pub fn length(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[LENGTH])
    }

    /// Return the `type` field
    pub fn message_type(&self) -> MessageType {
        let data = self.buffer.as_ref();
        MessageType::from(NativeEndian::read_u16(&data[MESSAGE_TYPE]))
    }

    /// Return the `flags` field
    pub fn flags(&self) -> Flags {
        let data = self.buffer.as_ref();
        Flags::from(NativeEndian::read_u16(&data[FLAGS]))
    }

    /// Return the `sequence_number` field
    pub fn sequence_number(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[SEQUENCE_NUMBER])
    }

    /// Return the `port_number` field
    pub fn port_number(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[PORT_NUMBER])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the `length` field
    pub fn set_length(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[LENGTH], value)
    }

    /// Set the `message_type` field
    pub fn set_message_type(&mut self, value: MessageType) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[MESSAGE_TYPE], value.into())
    }

    /// Set the `flags` field
    pub fn set_flags(&mut self, value: Flags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[FLAGS], value.into())
    }

    /// Set the `sequence_number` field
    pub fn set_sequence_number(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[SEQUENCE_NUMBER], value)
    }

    /// Set the `port_number` field
    pub fn set_port_number(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[PORT_NUMBER], value)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    // FIXME: should we provide a `payload_checked` to avoid panic, if the length is wrong in the
    // header?

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let range = PAYLOAD.start..self.length() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    // FIXME: should we provide a `payload_mut_checked` to avoid panic, if the length is wrong in
    // the header?

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = PAYLOAD.start..self.length() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct PacketRepr {
    pub length: u32,
    pub message_type: MessageType,
    pub flags: Flags,
    pub sequence_number: u32,
    pub port_number: u32,
}

impl Repr for PacketRepr {
    /// Parse a packet and return a high-level representation.
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        Ok(PacketRepr {
            length: packet.length(),
            message_type: packet.message_type(),
            flags: packet.flags(),
            sequence_number: packet.sequence_number(),
            port_number: packet.port_number(),
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    fn buffer_len(&self) -> usize {
        self.length as usize
    }

    /// Emit a high-level representation into a buffer
    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        let mut packet = Packet::new_checked(buffer)?;
        packet.set_message_type(self.message_type);
        packet.set_length(self.length);
        packet.set_flags(self.flags);
        packet.set_sequence_number(self.sequence_number);
        packet.set_port_number(self.port_number);
        Ok(())
    }
}
