use {Emitable, Parseable, Result};

use super::{LinkFlags, LinkLayerType, LinkNla, RtnlLinkBuffer, HEADER_LEN};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RtnlLinkHeader {
    pub address_family: u8,
    pub link_layer_type: LinkLayerType,
    pub flags: LinkFlags,
}

impl Emitable for RtnlLinkHeader {
    fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = RtnlLinkBuffer::new(buffer);
        packet.set_address_family(self.address_family);
        packet.set_link_layer_type(self.link_layer_type);
        packet.set_flags(self.flags);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RtnlLinkMessage {
    pub header: RtnlLinkHeader,
    pub nlas: Vec<LinkNla>,
}

impl Emitable for RtnlLinkMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        // in rust, we're guaranteed that when doing `a() + b(), a() is evaluated first
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<RtnlLinkMessage> for RtnlLinkBuffer<&'buffer T> {
    fn parse(&self) -> Result<RtnlLinkMessage> {
        Ok(RtnlLinkMessage {
            header: self.parse()?,
            nlas: self.parse()?,
        })
    }
}

// FIXME: we should make it possible to provide a "best effort" parsing method. Right now, if we
// fail on a single nla, we return an error. Maybe we could have another impl that returns
// Vec<Result<LinkNla>>.
impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<LinkNla>> for RtnlLinkBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<LinkNla>> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}

impl<T: AsRef<[u8]>> Parseable<RtnlLinkHeader> for RtnlLinkBuffer<T> {
    fn parse(&self) -> Result<RtnlLinkHeader> {
        Ok(RtnlLinkHeader {
            address_family: self.address_family(),
            link_layer_type: self.link_layer_type(),
            flags: self.flags(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use packet::rtnl::link::*;

    #[cfg_attr(nightly, allow(unused_attributes))]
    #[cfg_attr(nightly, rustfmt::skip)]
    static HEADER: [u8; 96] = [
        0x00, // address family
        0x00, // reserved
        0x04, 0x03, // link layer type 772 = loopback
        0x01, 0x00, 0x00, 0x00, // interface index = 1
        // Note: in the wireshark capture, the thrid byte is 0x01
        // but that does not correpond to any of the IFF_ flags...
        0x49, 0x00, 0x00, 0x00, // device flags: UP, LOOPBACK, RUNNING, LOWERUP
        0x00, 0x00, 0x00, 0x00, // reserved 2 (aka device change flag)

        // nlas
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
        let packet = RtnlLinkBuffer::new(&HEADER[0..16]);
        assert_eq!(packet.address_family(), 0);
        assert_eq!(packet.reserved_1(), 0);
        assert_eq!(packet.link_layer_type(), LinkLayerType::Loopback);
        assert_eq!(packet.link_index(), 1);
        assert_eq!(
            packet.flags(),
            LinkFlags::from(IFF_UP | IFF_LOOPBACK | IFF_RUNNING)
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
            let mut packet = RtnlLinkBuffer::new(&mut buf);
            packet.set_address_family(0);
            packet.set_reserved_1(0);
            packet.set_link_layer_type(LinkLayerType::Loopback);
            packet.set_link_index(1);
            let mut flags = LinkFlags::new();
            flags.set_up();
            flags.set_loopback();
            flags.set_running();
            packet.set_flags(flags);
            packet.set_reserved_2(0);
        }
        assert_eq!(&buf[..], &HEADER[0..16]);
    }

    #[test]
    fn packet_nlas_read() {
        let packet = RtnlLinkBuffer::new(&HEADER[..]);
        assert_eq!(packet.nlas().count(), 10);
        let mut nlas = packet.nlas();

        // device name L=7,T=3,V=lo
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 7);
        assert_eq!(nla.kind(), 3);
        assert_eq!(nla.value(), &[0x6c, 0x6f, 0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::IfName(String::from("lo")));

        // TxQueue length L=8,T=13,V=1000
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 13);
        assert_eq!(nla.value(), &[0xe8, 0x03, 0x00, 0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::TxQueueLen(1000));

        // OperState L=5,T=16,V=0 (unknown)
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 5);
        assert_eq!(nla.kind(), 16);
        assert_eq!(nla.value(), &[0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::OperState(0));

        // Link mode L=5,T=17,V=0
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 5);
        assert_eq!(nla.kind(), 17);
        assert_eq!(nla.value(), &[0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::LinkMode(0));

        // MTU L=8,T=4,V=65536
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 4);
        assert_eq!(nla.value(), &[0x00, 0x00, 0x01, 0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::Mtu(65_536));

        // 0x00, 0x00, 0x00, 0x00,
        // Group L=8,T=27,V=9
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 27);
        assert_eq!(nla.value(), &[0x00, 0x00, 0x00, 0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::Group(0));

        // Promiscuity L=8,T=30,V=0
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 30);
        assert_eq!(nla.value(), &[0x00, 0x00, 0x00, 0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::Promiscuity(0));

        // Number of Tx Queues L=8,T=31,V=1
        // 0x01, 0x00, 0x00, 0x00
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 31);
        assert_eq!(nla.value(), &[0x01, 0x00, 0x00, 0x00]);
        let parsed: LinkNla = nla.parse().unwrap();
        assert_eq!(parsed, LinkNla::NumTxQueues(1));
    }
}