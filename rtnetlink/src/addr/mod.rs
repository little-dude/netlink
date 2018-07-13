use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packet::{AddressCacheInfo, AddressHeader, AddressMessage, AddressNla};

use errors::{Error, ErrorKind};

mod handle;
pub use self::handle::*;

mod add;
pub use self::add::*;

mod del;
pub use self::del::*;

mod get;
pub use self::get::*;

mod flush;
pub use self::flush::*;

#[derive(Clone, Debug, Default)]
pub struct Address {
    // the header common to all address messages
    header: AddressHeader,

    // the attributes that come inside the body
    label: Option<String>,
    flags: Option<u32>,
    cache_info: AddressCacheInfo,
    attributes: Vec<AddressNla>,

    // Different types of IP addresses

    // Important comment:
    // IFA_ADDRESS is prefix address, rather than local interface address.
    // It makes no difference for normally configured broadcast interfaces,
    // but for point-to-point IFA_ADDRESS is DESTINATION address,
    // local address is supplied in IFA_LOCAL attribute.
    ifa_address: Option<IpAddr>,
    ifa_local: Option<IpAddr>,
    ifa_broadcast: Option<IpAddr>,
    ifa_anycast: Option<IpAddr>,
    ifa_multicast: Option<IpAddr>,
    ifa_unspec: Option<IpAddr>,
}

impl Address {
    pub fn new() -> Self {
        Address::default()
    }

    pub fn family(&self) -> u8 {
        self.header.family
    }

    pub fn family_mut(&mut self) -> &mut u8 {
        &mut self.header.family
    }

    pub fn set_family(&mut self, value: u8) -> &mut Self {
        self.header.family = value;
        self
    }

    pub fn prefix_len(&self) -> u8 {
        self.header.prefix_len
    }

    pub fn prefix_len_mut(&mut self) -> &mut u8 {
        &mut self.header.prefix_len
    }

    pub fn set_prefix_len(&mut self, value: u8) -> &mut Self {
        self.header.prefix_len = value;
        self
    }

    pub fn index(&self) -> u32 {
        self.header.index
    }

    pub fn index_mut(&mut self) -> &mut u32 {
        &mut self.header.index
    }

    pub fn set_index(&mut self, value: u32) -> &mut Self {
        self.header.index = value;
        self
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_ref().map(String::as_ref)
    }

    pub fn label_mut(&mut self) -> Option<&mut String> {
        self.label.as_mut()
    }

    pub fn set_label(&mut self, value: String) -> &mut Self {
        self.label = Some(value);
        self
    }

    pub fn flags(&self) -> u8 {
        self.header.flags
    }

    pub fn flags_mut(&mut self) -> &mut u8 {
        &mut self.header.flags
    }

    pub fn set_flags(&mut self, value: u8) -> &mut Self {
        self.header.flags = value;
        self
    }

    pub fn scope(&self) -> u8 {
        self.header.scope
    }

    pub fn scope_mut(&mut self) -> &mut u8 {
        &mut self.header.scope
    }

    pub fn set_scope(&mut self, value: u8) -> &mut Self {
        self.header.scope = value;
        self
    }

    pub fn ifa_address(&self) -> Option<IpAddr> {
        self.ifa_address
    }

    pub fn set_ifa_address(&mut self, value: IpAddr) -> &mut Self {
        self.ifa_address = Some(value);
        self
    }

    pub fn ifa_local(&self) -> Option<IpAddr> {
        self.ifa_local
    }

    pub fn set_ifa_local(&mut self, value: IpAddr) -> &mut Self {
        self.ifa_local = Some(value);
        self
    }

    pub fn ifa_unspec(&self) -> Option<IpAddr> {
        self.ifa_unspec
    }

    pub fn set_ifa_unspec(&mut self, value: IpAddr) -> &mut Self {
        self.ifa_unspec = Some(value);
        self
    }

    pub fn ifa_broadcast(&self) -> Option<IpAddr> {
        self.ifa_broadcast
    }

    pub fn set_ifa_broadcast(&mut self, value: IpAddr) -> &mut Self {
        self.ifa_broadcast = Some(value);
        self
    }

    pub fn ifa_anycast(&self) -> Option<IpAddr> {
        self.ifa_anycast
    }

    pub fn set_ifa_anycast(&mut self, value: IpAddr) -> &mut Self {
        self.ifa_anycast = Some(value);
        self
    }

    pub fn ifa_multicast(&self) -> Option<IpAddr> {
        self.ifa_multicast
    }

    pub fn set_ifa_multicast(&mut self, value: IpAddr) -> &mut Self {
        self.ifa_multicast = Some(value);
        self
    }

    //     /// Get the local interface address (the main address) as IpNetwork
    //     /// which is the ifa_local address (if specified) or ifa_address otherwise
    //     pub fn address(&self) -> Result<IpNetwork, Error> {
    //         if let Some(ip) = self.ifa_local {
    //             Ok(IpNetwork::new(ip, self.prefix_len())?)
    //         } else if let Some(ip) = self.ifa_address {
    //             Ok(IpNetwork::new(ip, self.prefix_len())?)
    //         } else {
    //             bail!("IP address not present")
    //         }
    //     }

    pub fn from_address_message(value: AddressMessage) -> Result<Self, Error> {
        let (header, mut nlas) = (value.header, value.nlas);
        let mut addr = Address::new();
        addr.header = header;
        for nla in nlas.drain(..) {
            match nla {
                AddressNla::Unspec(bytes) => {
                    addr.set_ifa_unspec(bytes_to_ip_addr(&bytes[..])?);
                }
                AddressNla::Address(bytes) => {
                    addr.set_ifa_address(bytes_to_ip_addr(&bytes[..])?);
                }
                AddressNla::Local(bytes) => {
                    addr.set_ifa_local(bytes_to_ip_addr(&bytes[..])?);
                }
                AddressNla::Label(label) => {
                    addr.label = Some(label);
                }
                AddressNla::Broadcast(bytes) => {
                    addr.set_ifa_broadcast(bytes_to_ip_addr(&bytes[..])?);
                }
                AddressNla::Anycast(bytes) => {
                    addr.set_ifa_anycast(bytes_to_ip_addr(&bytes[..])?);
                }
                AddressNla::CacheInfo(cache_info) => {
                    addr.cache_info = cache_info;
                }
                AddressNla::Multicast(bytes) => {
                    addr.set_ifa_multicast(bytes_to_ip_addr(&bytes[..])?);
                }
                AddressNla::Flags(flags) => {
                    addr.flags = Some(flags);
                }
                _ => addr.attributes.push(nla),
            }
        }
        Ok(addr)
    }
}

fn bytes_to_ip_addr(bytes: &[u8]) -> Result<IpAddr, Error> {
    match bytes.len() {
        4 => {
            let mut array = [0; 4];
            array.copy_from_slice(bytes);
            Ok(Ipv4Addr::from(array).into())
        }
        16 => {
            let mut array = [0; 16];
            array.copy_from_slice(bytes);
            Ok(Ipv6Addr::from(array).into())
        }
        _ => Err(ErrorKind::InvalidIp(bytes.to_vec()).into()),
    }
}
