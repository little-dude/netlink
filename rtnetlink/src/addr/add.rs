use futures::{Future, Stream};
use std::net::{IpAddr, Ipv4Addr};

use crate::packet::constants::{
    AF_INET, AF_INET6, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use crate::packet::{
    AddressMessage, AddressNla, NetlinkFlags, NetlinkMessage, NetlinkPayload, RtnlMessage,
};

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
    pub(crate) fn new(handle: Handle, index: u32, address: IpAddr, prefix_len: u8) -> Self {
        let mut message = AddressMessage::default();

        message.header.prefix_len = prefix_len;
        message.header.index = index;

        let address_vec = match address {
            IpAddr::V4(ipv4) => {
                message.header.family = AF_INET as u8;
                ipv4.octets().to_vec()
            }
            IpAddr::V6(ipv6) => {
                message.header.family = AF_INET6 as u8;
                ipv6.octets().to_vec()
            }
        };

        if address.is_multicast() {
            message.nlas.push(AddressNla::Multicast(address_vec));
        } else if address.is_unspecified() {
            message.nlas.push(AddressNla::Unspec(address_vec));
        } else {
            if address.is_ipv6() {
                message.nlas.push(AddressNla::Address(address_vec));
            } else {
                message.nlas.push(AddressNla::Address(address_vec.clone()));

                // for IPv4 the IFA_LOCAL address can be set to the same value as IFA_ADDRESS
                message.nlas.push(AddressNla::Local(address_vec));

                // set the IFA_BROADCAST address as well (IPv6 does not support broadcast)
                if prefix_len == 32 {
                    message
                        .nlas
                        .push(AddressNla::Broadcast(vec![0xff, 0xff, 0xff, 0xff]));
                } else {
                    let mask = Ipv4Addr::from(!((0xffff_ffff as u32) >> (prefix_len as u32)));
                    message
                        .nlas
                        .push(AddressNla::Broadcast(mask.octets().to_vec()));
                };
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
            if let NetlinkPayload::Error(ref err_message) = message.payload() {
                Err(ErrorKind::NetlinkError(err_message.clone()).into())
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
