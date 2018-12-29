use futures::{Future, Stream};
use ipnetwork::IpNetwork;

use crate::packet::constants::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use crate::packet::{AddressNla, NetlinkFlags, NetlinkMessage, RtnlMessage};

use super::AddressHandle;
use crate::{Error, ErrorKind, Handle};

use super::bytes_to_ip_addr;

lazy_static! {
    // Flags for `ip addr del`
    static ref DEL_FLAGS: NetlinkFlags =
        NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct AddressDelRequest {
    handle: Handle,
    index: u32,
    address: IpNetwork,
}

impl AddressDelRequest {
    pub(crate) fn new(handle: Handle, index: u32, address: IpNetwork) -> Self {
        AddressDelRequest {
            handle,
            index,
            address,
        }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let AddressDelRequest {
            handle,
            index,
            address,
        } = self;

        AddressHandle::new(handle.clone())
            .get()
            .execute()
            .filter(move |msg| {
                if msg.header.index != index {
                    return false;
                }
                if msg.header.prefix_len != address.prefix() {
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
                                    if ip == address.ip() {
                                        return true;
                                    } else {
                                        continue;
                                    }
                                }
                                Err(_) => continue,
                            };
                        }
                        _ => continue,
                    }
                }
                false
            })
            .map(move |msg| {
                let mut req = NetlinkMessage::from(RtnlMessage::DelAddress(msg));
                req.header_mut().set_flags(*DEL_FLAGS);
                handle.clone().request(req).for_each(|msg| {
                    if msg.is_error() {
                        Err(ErrorKind::NetlinkError(msg).into())
                    } else {
                        Ok(())
                    }
                })
            })
            // 0xff is arbitrary. It is the max amount of futures that will be
            // buffered.
            .buffer_unordered(0xff)
            // turn the stream into a future.
            .for_each(|()| Ok(()))
    }
}
