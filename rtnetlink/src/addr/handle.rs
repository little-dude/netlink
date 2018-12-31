use ipnetwork::IpNetwork;

use super::{AddressAddRequest, AddressDelRequest, AddressFlushRequest, AddressGetRequest};

use crate::Handle;

pub struct AddressHandle(Handle);

impl AddressHandle {
    pub fn new(handle: Handle) -> Self {
        AddressHandle(handle)
    }

    /// Retrieve the list of ip addresses (equivalent to `ip addr show`)
    pub fn get(&self) -> AddressGetRequest {
        AddressGetRequest::new(self.0.clone())
    }

    /// Add an ip address on an interface (equivalent to `ip addr add`)
    pub fn add(&self, index: u32, net: IpNetwork) -> AddressAddRequest {
        AddressAddRequest::new(self.0.clone(), index, net)
    }

    /// Delete all ip addresses on an interface with the given index (equivalent to `ip addr flush`)
    pub fn flush(self, index: u32) -> AddressFlushRequest {
        AddressFlushRequest::new(self.0.clone(), index)
    }

    /// Delete the given IP address on the interface with the given index
    pub fn del(self, index: u32, net: IpNetwork) -> AddressDelRequest {
        AddressDelRequest::new(self.0.clone(), index, net)
    }
}
