use super::{NetlinkBuffer, NetlinkFlags, NETLINK_HEADER_LEN};
use {Emitable, Parseable, Result};

/// A Netlink header representation.
///
/// A netlink header has the following structure:
///
/// ```no_rust
/// 0                8                16              24               32
/// +----------------+----------------+----------------+----------------+
/// |                 packet length (including header)                  |
/// +----------------+----------------+----------------+----------------+
/// |          message type           |              flags              |
/// +----------------+----------------+----------------+----------------+
/// |                           sequence number                         |
/// +----------------+----------------+----------------+----------------+
/// |                   port number (formerly known as PID)             |
/// +----------------+----------------+----------------+----------------+
/// ```
///
/// # Example: parsing a netlink header
///
/// ```rust
/// extern crate rtnetlink;
/// use rtnetlink::{NetlinkBuffer, NetlinkHeader, Parseable};
/// use rtnetlink::constants::{RTM_GETLINK, NLM_F_ROOT, NLM_F_REQUEST, NLM_F_MATCH};
///
/// // a packet captured with tcpdump that was sent when running `ip link show`
/// static PKT: [u8; 40] = [
///     0x28, 0x00, 0x00, 0x00, // length = 40
///     0x12, 0x00, // message type = 18 (RTM_GETLINK)
///     0x01, 0x03, // flags = Request + Specify Tree Root + Return All Matching
///     0x34, 0x0e, 0xf9, 0x5a, // sequence number = 1526271540
///     0x00, 0x00, 0x00, 0x00, // port id = 0
///     // payload
///     0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x08, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x00];
///
/// fn main() {
///     let pkt: NetlinkHeader = NetlinkBuffer::new_checked(&PKT[..]).unwrap().parse().unwrap();
///     assert_eq!(pkt.length(), 40);
///     assert_eq!(pkt.message_type(), RTM_GETLINK);
///     assert_eq!(pkt.sequence_number(), 1_526_271_540);
///     assert_eq!(pkt.port_number(), 0);
///     assert_eq!(u16::from(pkt.flags()), NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH);
/// }
/// ```
///
/// # Example: emitting a netlink header
///
/// ```
/// extern crate rtnetlink;
/// use rtnetlink::{NetlinkBuffer, NetlinkHeader, NetlinkFlags, Emitable};
/// use rtnetlink::constants::{RTM_GETLINK, NLM_F_ROOT, NLM_F_REQUEST, NLM_F_MATCH};
///
/// // a packet captured with tcpdump that was sent when running `ip link show`
/// static PKT: [u8; 40] = [
///     0x28, 0x00, 0x00, 0x00, // length = 40
///     0x12, 0x00, // message type = 18 (RTM_GETLINK)
///     0x01, 0x03, // flags = Request + Specify Tree Root + Return All Matching
///     0x34, 0x0e, 0xf9, 0x5a, // sequence number = 1526271540
///     0x00, 0x00, 0x00, 0x00, // port id = 0
///     // payload
///     0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x08, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x00];
///
/// fn main() {
///     let flags = NetlinkFlags::from(NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH);
///     let pkt = NetlinkHeader::new(40, RTM_GETLINK, flags, 0x5af9_0e34, 0);
///     assert_eq!(pkt.buffer_len(), 16);
///     let mut buf = vec![0; 16];
///     pkt.emit(&mut buf[..]);
///     assert_eq!(&buf[..], &PKT[..16]);
/// }
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
pub struct NetlinkHeader {
    /// Length of the netlink packet, including the header and the payload
    length: u32,

    /// NetlinkMessage type. The meaning of this field depends on the netlink protocol family in use.
    message_type: u16,

    /// Flags
    flags: NetlinkFlags,

    /// Sequence number of the packet
    sequence_number: u32,

    /// Port number (usually set to the the process ID)
    port_number: u32,
}

impl NetlinkHeader {
    /// Create a new header, initialized with the given values
    pub fn new(
        length: u32,
        message_type: u16,
        flags: NetlinkFlags,
        sequence_number: u32,
        port_number: u32,
    ) -> Self {
        NetlinkHeader {
            length,
            message_type,
            flags,
            sequence_number,
            port_number,
        }
    }

    /// Get the length field
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Get a mutable reference to the length field
    pub fn length_mut(&mut self) -> &mut u32 {
        &mut self.length
    }

    /// Setter for the length field
    pub fn set_length(&mut self, value: u32) -> &mut Self {
        self.length = value;
        self
    }

    /// Get the message type field
    pub fn message_type(&self) -> u16 {
        self.message_type
    }

    /// Get a mutable reference to the message type field
    pub fn message_type_mut(&mut self) -> &mut u16 {
        &mut self.message_type
    }

    /// Setter for the message_type field
    pub fn set_message_type(&mut self, value: u16) -> &mut Self {
        self.message_type = value;
        self
    }

    /// Get the flags field
    pub fn flags(&self) -> NetlinkFlags {
        self.flags
    }

    /// Get a mutable reference to the flags field
    pub fn flags_mut(&mut self) -> &mut NetlinkFlags {
        &mut self.flags
    }

    /// Setter for the flags field
    pub fn set_flags(&mut self, value: NetlinkFlags) -> &mut Self {
        self.flags = value;
        self
    }

    /// Get the sequence number field
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// Get a mutable reference to the sequence number field
    pub fn sequence_number_mut(&mut self) -> &mut u32 {
        &mut self.sequence_number
    }

    /// Setter for the sequence number field
    pub fn set_sequence_number(&mut self, value: u32) -> &mut Self {
        self.sequence_number = value;
        self
    }

    /// Get the port number field
    pub fn port_number(&self) -> u32 {
        self.port_number
    }

    /// Get a mutable reference to the port number field
    pub fn port_number_mut(&mut self) -> &mut u32 {
        &mut self.port_number
    }

    /// Setter for the port number field
    pub fn set_port_number(&mut self, value: u32) -> &mut Self {
        self.port_number = value;
        self
    }
}

impl Emitable for NetlinkHeader {
    fn buffer_len(&self) -> usize {
        NETLINK_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NetlinkBuffer::new(buffer);
        buffer.set_message_type(self.message_type);
        buffer.set_length(self.length);
        buffer.set_flags(self.flags);
        buffer.set_sequence_number(self.sequence_number);
        buffer.set_port_number(self.port_number);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NetlinkHeader> for NetlinkBuffer<&'a T> {
    fn parse(&self) -> Result<NetlinkHeader> {
        Ok(NetlinkHeader {
            length: self.length(),
            message_type: self.message_type(),
            flags: self.flags(),
            sequence_number: self.sequence_number(),
            port_number: self.port_number(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use constants::*;
    use packets::flags::*;

    // a packet captured with tcpdump that was sent when running `ip link show`
    #[cfg_attr(nightly, rustfmt::skip)]
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
    fn repr_parse() {
        let repr: NetlinkHeader = NetlinkBuffer::new_checked(&IP_LINK_SHOW_PKT[..])
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(repr.length, 40);
        assert_eq!(repr.message_type, RTM_GETLINK);
        assert_eq!(repr.sequence_number, 1_526_271_540);
        assert_eq!(repr.port_number, 0);
        assert_eq!(
            Into::<u16>::into(repr.flags),
            NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH
        );
    }

    #[test]
    fn repr_emit() {
        let repr = NetlinkHeader {
            length: 40,
            message_type: RTM_GETLINK,
            sequence_number: 1_526_271_540,
            flags: NetlinkFlags::from(NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH),
            port_number: 0,
        };
        assert_eq!(repr.buffer_len(), 16);
        let mut buf = vec![0; 16];
        repr.emit(&mut buf[..]);
        assert_eq!(&buf[..], &IP_LINK_SHOW_PKT[..16]);
    }
}
