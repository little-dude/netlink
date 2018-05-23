use byteorder::{ByteOrder, NativeEndian};
use packet::utils::field::{Field, Rest};
use packet::{Error, Flags, MessageType, Result};

const LENGTH: Field = 0..4;
const MESSAGE_TYPE: Field = 4..6;
const FLAGS: Field = 6..8;
const SEQUENCE_NUMBER: Field = 8..12;
const PORT_NUMBER: Field = 12..16;
const PAYLOAD: Rest = 16..;

pub const HEADER_LEN: usize = PAYLOAD.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Buffer<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Buffer<T> {
    pub fn new(buffer: T) -> Buffer<T> {
        Buffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Buffer<T>> {
        let packet = Self::new(buffer);
        packet.check_buffer_length()?;
        Ok(packet)
    }

    pub fn check_buffer_length(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < PORT_NUMBER.end || len < self.length() as usize {
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

impl<T: AsRef<[u8]> + AsMut<[u8]>> Buffer<T> {
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

impl<'a, T: AsRef<[u8]> + ?Sized> Buffer<&'a T> {
    // FIXME: should we provide a `payload_checked` to avoid panic, if the length is wrong in the
    // header?

    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let range = PAYLOAD.start..self.length() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Buffer<&'a mut T> {
    // FIXME: should we provide a `payload_mut_checked` to avoid panic, if the length is wrong in
    // the header?

    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = PAYLOAD.start..self.length() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Header {
    pub length: u32,
    pub message_type: MessageType,
    pub flags: Flags,
    pub sequence_number: u32,
    pub port_number: u32,
}

impl Header {
    /// Parse a packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(buffer: &Buffer<&T>) -> Result<Self> {
        Ok(Header {
            length: buffer.length(),
            message_type: buffer.message_type(),
            flags: buffer.flags(),
            sequence_number: buffer.sequence_number(),
            port_number: buffer.port_number(),
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        PAYLOAD.start
    }

    /// Emit a high-level representation into a buffer
    pub fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() < self.buffer_len() {
            return Err(Error::Exhausted);
        }
        let mut buffer = Buffer::new(buffer);
        buffer.set_message_type(self.message_type);
        buffer.set_length(self.length);
        buffer.set_flags(self.flags);
        buffer.set_sequence_number(self.sequence_number);
        buffer.set_port_number(self.port_number);
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
        let packet = Buffer::new(&IP_LINK_SHOW_PKT[..]);
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
        assert_eq!(
            Into::<u16>::into(flags),
            NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH
        );
    }

    #[test]
    fn packet_build() {
        let mut buf = vec![0; 40];
        {
            let mut packet = Buffer::new(&mut buf);
            packet.set_length(40);
            packet.set_message_type(MessageType::GetLink);
            packet.set_sequence_number(1526271540);
            packet.set_port_number(0);
            packet.set_flags(From::from(NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH));
            packet
                .payload_mut()
                .copy_from_slice(&IP_LINK_SHOW_PKT[16..]);
        }
        assert_eq!(&buf[..], &IP_LINK_SHOW_PKT[..]);
    }

    #[test]
    fn repr_parse() {
        let repr = Header::parse(&Buffer::new_checked(&IP_LINK_SHOW_PKT[..]).unwrap()).unwrap();
        assert_eq!(repr.length, 40);
        assert_eq!(repr.message_type, MessageType::GetLink);
        assert_eq!(repr.sequence_number, 1526271540);
        assert_eq!(repr.port_number, 0);
        assert!(repr.flags.has_root());
        assert!(repr.flags.has_request());
        assert!(repr.flags.has_match());
        assert_eq!(
            Into::<u16>::into(repr.flags),
            NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH
        );
    }

    #[test]
    fn repr_emit() {
        let repr = Header {
            length: 40,
            message_type: MessageType::GetLink,
            sequence_number: 1526271540,
            flags: Flags::from(NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH),
            port_number: 0,
        };
        assert_eq!(repr.buffer_len(), 16);
        let mut buf = vec![0; 16];
        repr.emit(&mut buf[..]).unwrap();
        assert_eq!(&buf[..], &IP_LINK_SHOW_PKT[..16]);
    }
}
