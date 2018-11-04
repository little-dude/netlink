use super::bytes_to_ip_addr;
use connection::ConnectionHandle;
use errors::NetlinkIpError;
use futures::Future;
use ipnetwork::IpNetwork;
use rtnetlink::AddressNla;

use super::{AddressAddRequest, AddressDelRequest, AddressDelRequestFuture, AddressGetRequest};

pub struct AddressHandle(ConnectionHandle);

impl AddressHandle {
    pub fn new(handle: ConnectionHandle) -> Self {
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
    pub fn flush(
        self,
        index: u32,
    ) -> AddressDelRequestFuture<impl Future<Item = AddressDelRequest, Error = NetlinkIpError>>
    {
        // get all addresses first
        // then create a delete request with all address messages included
        let future = self.get().get_address_msgs_future().map(move |addr_msgs| {
            let msgs = addr_msgs
                .into_iter()
                .filter(|msg| msg.header.index == index)
                .collect::<Vec<_>>();
            AddressDelRequest::new(self.0.clone(), msgs)
        });
        AddressDelRequestFuture(future)
    }

    /// Delete the given IP address on the interface with the given index
    pub fn del(
        self,
        index: u32,
        net: IpNetwork,
    ) -> AddressDelRequestFuture<impl Future<Item = AddressDelRequest, Error = NetlinkIpError>>
    {
        // get all address messages first, find the one matching the given IPNetwork
        // then create a delete request with the corresponding address message included
        let future = self.get().get_address_msgs_future().map(move |addr_msgs| {
            let msgs = addr_msgs
                .into_iter()
                .filter(|msg| msg.header.index == index)
                .find(|msg| {
                    if msg.header.prefix_len != net.prefix() {
                        return false;
                    }
                    for nla in msg.nlas.iter() {
                        match nla {
                            AddressNla::Unspec(bytes)
                            | AddressNla::Address(bytes)
                            | AddressNla::Local(bytes)
                            | AddressNla::Multicast(bytes)
                            | AddressNla::Anycast(bytes) => {
                                match bytes_to_ip_addr(&bytes[..]) {
                                    Ok(ip) => {
                                        if ip == net.ip() {
                                            return true;
                                        }
                                    }
                                    Err(_) => continue,
                                };
                            }
                            _ => continue,
                        }
                    }
                    return false;
                }).map(|msg| vec![msg])
                .unwrap_or(vec![]);
            AddressDelRequest::new(self.0.clone(), msgs)
        });
        AddressDelRequestFuture(future)
    }
}
