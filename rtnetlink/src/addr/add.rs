use futures::{Future, Stream};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

use crate::packet::constants::{AF_INET, AF_INET6, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use crate::packet::{AddressMessage, AddressNla, NetlinkFlags, NetlinkMessage, RtnlMessage};

use crate::{Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip addr add`
    static ref ADD_FLAGS: NetlinkFlags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

/// A request to create a new address. This is equivalent to the `ip address add` commands.
pub struct AddressAddRequest {
    handle: Handle,
    message: AddressMessage,
}

impl AddressAddRequest {
    pub(crate) fn new(handle: Handle, index: u32, net: IpNetwork) -> Self {
        let mut message = AddressMessage::default();
        if net.is_ipv4() {
            message.header.family = AF_INET as u8
        } else {
            message.header.family = AF_INET6 as u8
        };
        message.header.prefix_len = net.prefix();
        message.header.index = index;

        let ip = net.ip();

        if ip.is_multicast() {
            let nla = AddressNla::Multicast(ip_to_vec(ip));
            message.nlas.push(nla);
        } else if ip.is_unspecified() {
            let nla = AddressNla::Unspec(ip_to_vec(ip));
            message.nlas.push(nla);
        } else {
            let nla = AddressNla::Address(ip_to_vec(ip));
            message.nlas.push(nla);

            // for IPv4 the IFA_LOCAL address can be set to the same value as IFA_ADDRESS
            if ip.is_ipv4() {
                let nla = AddressNla::Local(ip_to_vec(ip));
                message.nlas.push(nla);
            }

            // for IPv4 set the IFA_BROADCAST address as well (IPv6 does not support broadcast)
            if let IpNetwork::V4(n) = net {
                let bytes = n.broadcast().octets().to_vec();
                let nla = AddressNla::Broadcast(bytes);
                message.nlas.push(nla);
            }
        }
        AddressAddRequest { handle, message }
    }

    /// Execute the request.
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let AddressAddRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::NewAddress(message));
        req.header_mut().set_flags(*ADD_FLAGS);
        handle.request(req).for_each(|message| {
            if message.is_error() {
                Err(ErrorKind::NetlinkError(message).into())
            } else {
                Ok(())
            }
        })
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut AddressMessage {
        &mut self.message
    }
}

// convert an IP address to a Vec<u8>
fn ip_to_vec(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(i) => i.octets().to_vec(),
        IpAddr::V6(i) => i.octets().to_vec(),
    }
}
