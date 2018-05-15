use super::{field, Error, Flags, MessageType, Repr, Result};
use byteorder::{ByteOrder, NativeEndian};

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
pub struct HeaderRepr {
    pub length: u32,
    pub message_type: MessageType,
    pub flags: Flags,
    pub sequence_number: u32,
    pub port_number: u32,
}

impl Repr for HeaderRepr {
    /// Parse a packet and return a high-level representation.
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        Ok(HeaderRepr {
            length: packet.length(),
            message_type: packet.message_type(),
            flags: packet.flags(),
            sequence_number: packet.sequence_number(),
            port_number: packet.port_number(),
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    fn buffer_len(&self) -> usize {
        PAYLOAD.start
    }

    /// Emit a high-level representation into a buffer
    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() < self.buffer_len() {
            return Err(Error::Exhausted);
        }
        let mut packet = Packet::new(buffer);
        packet.set_message_type(self.message_type);
        packet.set_length(self.length);
        packet.set_flags(self.flags);
        packet.set_sequence_number(self.sequence_number);
        packet.set_port_number(self.port_number);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::flags::*;

    // a packet captured with tcpdump that was sent when running `ip link show`
    #[allow(unused_attributes)]
    #[rustfmt_skip]
    static IP_LINK_SHOW_PKT: [u8; 40] = [
        0x28, 0x00, 0x00, 0x00, // length = 40
        0x12, 0x00, // message type = 18 (RTM_GETLINK)
        0x01, 0x03, // flags = Request + Specify Tree Root + Return All Matching
        0x34, 0x0e, 0xf9, 0x5a, // sequence number = 1526271540
        0x00, 0x00, 0x00, 0x00, // port id = 0
        // payload
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn packet_read() {
        let packet = Packet::new(&IP_LINK_SHOW_PKT[..]);
        assert_eq!(packet.length(), 40);
        assert_eq!(packet.message_type(), MessageType::GetLink);
        assert_eq!(packet.sequence_number(), 1526271540);
        assert_eq!(packet.port_number(), 0);
        let flags = packet.flags();
        assert!(flags.has_root());
        assert!(flags.has_request());
        assert!(flags.has_match());
        assert_eq!(packet.payload_length().unwrap(), 24);
        assert_eq!(packet.payload(), &IP_LINK_SHOW_PKT[16..]);
        assert_eq!(Into::<u16>::into(flags), ROOT | REQUEST | MATCH);
    }

    #[test]
    fn packet_build() {
        let mut buf = vec![0; 40];
        {
            let mut packet = Packet::new(&mut buf);
            packet.set_length(40);
            packet.set_message_type(MessageType::GetLink);
            packet.set_sequence_number(1526271540);
            packet.set_port_number(0);
            packet.set_flags(From::from(ROOT | REQUEST | MATCH));
            packet
                .payload_mut()
                .copy_from_slice(&IP_LINK_SHOW_PKT[16..]);
        }
        assert_eq!(&buf[..], &IP_LINK_SHOW_PKT[..]);
    }

    #[test]
    fn repr_parse() {
        let repr = HeaderRepr::parse(&IP_LINK_SHOW_PKT[..]).unwrap();
        assert_eq!(repr.length, 40);
        assert_eq!(repr.message_type, MessageType::GetLink);
        assert_eq!(repr.sequence_number, 1526271540);
        assert_eq!(repr.port_number, 0);
        assert!(repr.flags.has_root());
        assert!(repr.flags.has_request());
        assert!(repr.flags.has_match());
        assert_eq!(Into::<u16>::into(repr.flags), ROOT | REQUEST | MATCH);
    }

    #[test]
    fn repr_emit() {
        let repr = HeaderRepr {
            length: 40,
            message_type: MessageType::GetLink,
            sequence_number: 1526271540,
            flags: Flags::from(ROOT | REQUEST | MATCH),
            port_number: 0,
        };
        assert_eq!(repr.buffer_len(), 16);
        let mut buf = vec![0; 16];
        repr.emit(&mut buf[..]).unwrap();
        assert_eq!(&buf[..], &IP_LINK_SHOW_PKT[..16]);
    }
}
