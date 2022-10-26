// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

pub const XFRM_ADDRESS_LEN: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Address {
    // Xfrm netlink API simply uses a 16 byte buffer for both IPv4 & IPv6
    // addresses and unfortunately doesn't always pair it with a family type.
    pub addr: [u8; XFRM_ADDRESS_LEN],
}

buffer!(AddressBuffer(XFRM_ADDRESS_LEN) {
    addr: (slice, 0..XFRM_ADDRESS_LEN)
});

impl<T: AsRef<[u8]> + ?Sized> Parseable<AddressBuffer<&T>> for Address {
    fn parse(buf: &AddressBuffer<&T>) -> Result<Self, DecodeError> {
        let mut addr_payload: [u8; XFRM_ADDRESS_LEN] = [0; XFRM_ADDRESS_LEN];
        addr_payload.clone_from_slice(&buf.addr());
        Ok(Address { addr: addr_payload })
    }
}

impl Emitable for Address {
    fn buffer_len(&self) -> usize {
        XFRM_ADDRESS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = AddressBuffer::new(buffer);
        buffer.addr_mut().clone_from_slice(&self.addr[..]);
    }
}

impl Address {
    pub fn to_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.addr[0], self.addr[1], self.addr[2], self.addr[3])
    }

    pub fn to_ipv6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.addr)
    }

    pub fn from_ipv4(ip: &Ipv4Addr) -> Address {
        let mut addr_bytes: [u8; XFRM_ADDRESS_LEN] = [0; XFRM_ADDRESS_LEN];
        addr_bytes[0] = ip.octets()[0];
        addr_bytes[1] = ip.octets()[1];
        addr_bytes[2] = ip.octets()[2];
        addr_bytes[3] = ip.octets()[3];
        Address { addr: addr_bytes }
    }

    pub fn from_ipv6(ip: &Ipv6Addr) -> Address {
        Address { addr: ip.octets() }
    }
}
