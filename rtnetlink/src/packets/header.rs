use super::{NetlinkBuffer, NetlinkFlags, NETLINK_HEADER_LEN};
use {Emitable, Parseable, Result};

/// A Netlink header representation. For more details about the meaning of the fields, see `man 7 netlink`
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
pub struct NetlinkHeader {
    /// Length of the netlink packet, including the header and the payload
    pub length: u32,

    /// NetlinkMessage type. The meaning of this field depends on the netlink protocol family in use.
    pub message_type: u16,

    /// Flags
    pub flags: NetlinkFlags,

    /// Sequence number of the packet
    pub sequence_number: u32,

    /// Port number (usually set to the the process ID)
    pub port_number: u32,
}

impl NetlinkHeader {
    pub fn length(&self) -> u32 {
        self.length
    }

    pub fn length_mut(&mut self) -> &mut u32 {
        &mut self.length
    }

    pub fn set_length(&mut self, value: u32) -> &mut Self {
        self.length = value;
        self
    }

    pub fn message_type(&self) -> u16 {
        self.message_type
    }

    pub fn message_type_mut(&mut self) -> &mut u16 {
        &mut self.message_type
    }

    pub fn set_message_type(&mut self, value: u16) -> &mut Self {
        self.message_type = value;
        self
    }

    pub fn flags(&self) -> NetlinkFlags {
        self.flags
    }

    pub fn flags_mut(&mut self) -> &mut NetlinkFlags {
        &mut self.flags
    }

    pub fn set_flags(&mut self, value: NetlinkFlags) -> &mut Self {
        self.flags = value;
        self
    }

    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub fn sequence_number_mut(&mut self) -> &mut u32 {
        &mut self.sequence_number
    }

    pub fn set_sequence_number(&mut self, value: u32) -> &mut Self {
        self.sequence_number = value;
        self
    }

    pub fn port_number(&self) -> u32 {
        self.port_number
    }

    pub fn port_number_mut(&mut self) -> &mut u32 {
        &mut self.port_number
    }

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
