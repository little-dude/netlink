use byteorder::{ByteOrder, NativeEndian};
use packet::attribute::AttributesIterator;
use packet::field;
use packet::link::Flags;
use packet::link::LinkAttribute;
use packet::link::LinkLayerType;

const ADDRESS_FAMILY: field::Index = 0;
const RESERVED_1: field::Index = 1;
const LINK_LAYER_TYPE: field::Field = 2..4;
const LINK_INDEX: field::Field = 4..8;
const FLAGS: field::Field = 8..12;
const RESERVED_2: field::Field = 12..16;
const ATTRIBUTES: field::Rest = 16..;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Buffer<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Buffer<T> {
    pub fn new(buffer: T) -> Buffer<T> {
        Buffer { buffer }
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

    /// Return the link layer type field
    pub fn reserved_1(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[RESERVED_1]
    }

    /// Return the link layer type field
    pub fn link_layer_type(&self) -> LinkLayerType {
        let data = self.buffer.as_ref();
        LinkLayerType::from(NativeEndian::read_u16(&data[LINK_LAYER_TYPE]))
    }

    /// Return the link index field
    pub fn link_index(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[LINK_INDEX])
    }

    /// Return the flags field
    pub fn flags(&self) -> Flags {
        let data = self.buffer.as_ref();
        Flags::from(NativeEndian::read_u32(&data[FLAGS]))
    }

    /// Return the link index field
    pub fn reserved_2(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[RESERVED_2])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Buffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn attributes(&self) -> AttributesIterator<'a> {
        AttributesIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Buffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Buffer<T> {
    /// set the address family field
    pub fn set_address_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[ADDRESS_FAMILY] = value
    }

    pub fn set_reserved_1(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[RESERVED_1] = value
    }

    pub fn set_link_layer_type(&mut self, value: LinkLayerType) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[LINK_LAYER_TYPE], value.into())
    }

    pub fn set_link_index(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[LINK_INDEX], value)
    }

    pub fn set_flags(&mut self, value: Flags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[FLAGS], value.into())
    }

    pub fn set_reserved_2(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[RESERVED_2], value)
    }
}

pub struct Message {
    pub address_family: u8,
    pub link_layer_type: LinkLayerType,
    pub flags: Flags,
    pub attributes: Vec<LinkAttribute>,
}

#[cfg(test)]
mod test {
    use super::*;
    use packet::link::flags::*;
    use packet::link::link_layer_type::*;
    #[allow(unused_attributes)]
    #[rustfmt_skip]
    static HEADER: [u8; 96] = [
        0x00, // address family
        0x00, // reserved
        0x04, 0x03, // link layer type 772 = loopback
        0x01, 0x00, 0x00, 0x00, // interface index = 1
        // Note: in the wireshark capture, the thrid byte is 0x01
        // but that does not correpond to any of the IFF_ flags...
        0x49, 0x00, 0x00, 0x00, // device flags: UP, LOOPBACK, RUNNING, LOWERUP
        0x00, 0x00, 0x00, 0x00, // reserved 2 (aka device change flag)

        // attributes
        0x07, 0x00, 0x03, 0x00, 0x6c, 0x6f, 0x00, // device name L=7,T=3,V=lo
        0x00, // padding
        0x08, 0x00, 0x0d, 0x00, 0xe8, 0x03, 0x00, 0x00, // TxQueue length L=8,T=13,V=1000
        0x05, 0x00, 0x10, 0x00, 0x00, // OperState L=5,T=16,V=0 (unknown)
        0x00, 0x00, 0x00, // padding
        0x05, 0x00, 0x11, 0x00, 0x00, // Link mode L=5,T=17,V=0
        0x00, 0x00, 0x00, // padding
        0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, // MTU L=8,T=4,V=65536
        0x08, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, // Group L=8,T=27,V=9
        0x08, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, // Promiscuity L=8,T=30,V=0
        0x08, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00, // Number of Tx Queues L=8,T=31,V=1
        0x08, 0x00, 0x28, 0x00, 0xff, 0xff, 0x00, 0x00, // Maximum GSO segment count L=8,T=40,V=65536
        0x08, 0x00, 0x29, 0x00, 0x00, 0x00, 0x01, 0x00, // Maximum GSO size L=8,T=41,V=65536
    ];

    #[test]
    fn packet_header_read() {
        let packet = Buffer::new(&HEADER[0..16]);
        assert_eq!(packet.address_family(), 0);
        assert_eq!(packet.reserved_1(), 0);
        assert_eq!(packet.link_layer_type(), LinkLayerType::Loopback);
        assert_eq!(packet.link_index(), 1);
        assert_eq!(
            packet.flags(),
            Flags::from(IFF_UP | IFF_LOOPBACK | IFF_RUNNING)
        );
        assert!(packet.flags().has_running());
        assert!(packet.flags().has_loopback());
        assert!(packet.flags().has_up());
        assert_eq!(packet.reserved_2(), 0);
    }

    #[test]
    fn packet_header_build() {
        let mut buf = vec![0xff; 16];
        {
            let mut packet = Buffer::new(&mut buf);
            packet.set_address_family(0);
            packet.set_reserved_1(0);
            packet.set_link_layer_type(LinkLayerType::Loopback);
            packet.set_link_index(1);
            let mut flags = Flags::new();
            flags.set_up();
            flags.set_loopback();
            flags.set_running();
            packet.set_flags(flags);
            packet.set_reserved_2(0);
        }
        assert_eq!(&buf[..], &HEADER[0..16]);
    }

    #[test]
    fn packet_attributes_read() {
        use packet::attribute::Attribute;

        let packet = Buffer::new(&HEADER[..]);
        assert_eq!(packet.attributes().count(), 10);
        let mut attributes = packet.attributes();

        // device name L=7,T=3,V=lo
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 7);
        assert_eq!(attr.kind(), 3);
        assert_eq!(attr.value(), &[0x6c, 0x6f, 0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::Ifname(String::from("lo")));

        // TxQueue length L=8,T=13,V=1000
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 8);
        assert_eq!(attr.kind(), 13);
        assert_eq!(attr.value(), &[0xe8, 0x03, 0x00, 0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::TxQueueLen(1000));

        // OperState L=5,T=16,V=0 (unknown)
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 5);
        assert_eq!(attr.kind(), 16);
        assert_eq!(attr.value(), &[0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::OperState(0));

        // Link mode L=5,T=17,V=0
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 5);
        assert_eq!(attr.kind(), 17);
        assert_eq!(attr.value(), &[0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::LinkMode(0));

        // MTU L=8,T=4,V=65536
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 8);
        assert_eq!(attr.kind(), 4);
        assert_eq!(attr.value(), &[0x00, 0x00, 0x01, 0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::Mtu(65_536));

        // 0x00, 0x00, 0x00, 0x00,
        // Group L=8,T=27,V=9
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 8);
        assert_eq!(attr.kind(), 27);
        assert_eq!(attr.value(), &[0x00, 0x00, 0x00, 0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::Group(0));

        // Promiscuity L=8,T=30,V=0
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 8);
        assert_eq!(attr.kind(), 30);
        assert_eq!(attr.value(), &[0x00, 0x00, 0x00, 0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::Promiscuity(0));

        // Number of Tx Queues L=8,T=31,V=1
        // 0x01, 0x00, 0x00, 0x00
        let attr = attributes.next().unwrap().unwrap();
        attr.check_buffer_length().unwrap();
        assert_eq!(attr.length(), 8);
        assert_eq!(attr.kind(), 31);
        assert_eq!(attr.value(), &[0x01, 0x00, 0x00, 0x00]);
        let parsed = LinkAttribute::from_packet(attr).unwrap();
        assert_eq!(parsed, LinkAttribute::NumTxQueues(1));
    }
}
