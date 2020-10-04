use byteorder::{BigEndian, ByteOrder};
use std::{
    convert::{TryFrom, TryInto},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{
    constants::*,
    traits::{Emitable, ParseableParametrized},
    DecodeError,
};

pub const SOCKET_ID_LEN: usize = 48;

buffer!(SocketIdBuffer(SOCKET_ID_LEN) {
    source_port: (slice, 0..2),
    destination_port: (slice, 2..4),
    source_address: (slice, 4..20),
    destination_address: (slice, 20..36),
    interface_id: (u32, 36..40),
    cookie: (slice, 40..48),
});

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SocketId {
    pub source_port: u16,
    pub destination_port: u16,
    pub source_address: IpAddr,
    pub destination_address: IpAddr,
    pub interface_id: u32,
    /// An array of opaque identifiers that could be used along with
    /// other fields of this structure to specify an individual
    /// socket. It is ignored when querying for a list of sockets, as
    /// well as when all its elements are set to `0xff`.
    pub cookie: [u8; 8],
}

impl SocketId {
    pub fn new_v4() -> Self {
        Self {
            source_port: 0,
            destination_port: 0,
            source_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            destination_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            interface_id: 0,
            cookie: [0; 8],
        }
    }
    pub fn new_v6() -> Self {
        Self {
            source_port: 0,
            destination_port: 0,
            source_address: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            destination_address: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            interface_id: 0,
            cookie: [0; 8],
        }
    }
}

impl<'a, T: AsRef<[u8]> + 'a> ParseableParametrized<SocketIdBuffer<&'a T>, u8> for SocketId {
    fn parse_with_param(buf: &SocketIdBuffer<&'a T>, af: u8) -> Result<Self, DecodeError> {
        let (source_address, destination_address) = match af {
            AF_INET => {
                let s = &buf.source_address()[..4];
                let source = IpAddr::V4(Ipv4Addr::new(s[0], s[1], s[2], s[3]));

                let s = &buf.destination_address()[..4];
                let destination = IpAddr::V4(Ipv4Addr::new(s[0], s[1], s[2], s[3]));

                (source, destination)
            }
            AF_INET6 => {
                let bytes: [u8; 16] = buf.source_address().try_into().unwrap();
                let source = IpAddr::V6(Ipv6Addr::from(bytes));

                let bytes: [u8; 16] = buf.destination_address().try_into().unwrap();
                let destination = IpAddr::V6(Ipv6Addr::from(bytes));
                (source, destination)
            }
            _ => {
                return Err(DecodeError::from(format!(
                    "unsupported address family {}: expected AF_INET ({}) or AF_INET6 ({})",
                    af, AF_INET, AF_INET6
                )));
            }
        };

        Ok(Self {
            source_port: BigEndian::read_u16(buf.source_port()),
            destination_port: BigEndian::read_u16(buf.destination_port()),
            source_address,
            destination_address,
            interface_id: buf.interface_id(),
            // Unwrapping is safe because SocketIdBuffer::cookie()
            // returns a slice of exactly 8 bytes.
            cookie: TryFrom::try_from(buf.cookie()).unwrap(),
        })
    }
}

impl Emitable for SocketId {
    fn buffer_len(&self) -> usize {
        SOCKET_ID_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = SocketIdBuffer::new(buffer);

        BigEndian::write_u16(buffer.source_port_mut(), self.source_port);
        BigEndian::write_u16(buffer.destination_port_mut(), self.destination_port);

        let mut address_buf: [u8; 16] = [0; 16];
        match self.source_address {
            IpAddr::V4(ip) => (&mut address_buf[0..4]).copy_from_slice(&ip.octets()[..]),
            IpAddr::V6(ip) => address_buf.copy_from_slice(&ip.octets()[..]),
        }

        buffer
            .source_address_mut()
            .copy_from_slice(&address_buf[..]);

        address_buf = [0; 16];
        match self.destination_address {
            IpAddr::V4(ip) => (&mut address_buf[0..4]).copy_from_slice(&ip.octets()[..]),
            IpAddr::V6(ip) => address_buf.copy_from_slice(&ip.octets()[..]),
        }

        buffer
            .destination_address_mut()
            .copy_from_slice(&address_buf[..]);

        buffer.set_interface_id(self.interface_id);
        buffer.cookie_mut().copy_from_slice(&self.cookie[..]);
    }
}
