use futures::{Future, Stream};
use std::net::IpAddr;

use crate::packet::constants::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use crate::packet::{AddressNla, NetlinkFlags, NetlinkMessage, NetlinkPayload, RtnlMessage};

use super::AddressHandle;
use crate::{Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip addr del`
    static ref DEL_FLAGS: NetlinkFlags =
        NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct AddressDelRequest {
    handle: Handle,
    index: u32,
    address: IpAddr,
    prefix_len: u8,
}

impl AddressDelRequest {
    pub(crate) fn new(handle: Handle, index: u32, address: IpAddr, prefix_len: u8) -> Self {
        AddressDelRequest {
            handle,
            index,
            address,
            prefix_len,
        }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let AddressDelRequest {
            handle,
            index,
            address,
            prefix_len,
        } = self;

        AddressHandle::new(handle.clone())
            .get()
            .execute()
            .filter(move |msg| {
                if msg.header.index != index {
                    return false;
                }
                if msg.header.prefix_len != prefix_len {
                    return false;
                }
                for nla in msg.nlas.iter() {
                    match nla {
                        AddressNla::Unspec(bytes)
                        | AddressNla::Address(bytes)
                        | AddressNla::Local(bytes)
                        | AddressNla::Multicast(bytes)
                        | AddressNla::Anycast(bytes) => {
                            let is_match = match address {
                                IpAddr::V4(address) => bytes[..] == address.octets()[..],
                                IpAddr::V6(address) => bytes[..] == address.octets()[..],
                            };
                            if is_match {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
                false
            })
            .map(move |msg| {
                let mut req = NetlinkMessage::from(RtnlMessage::DelAddress(msg));
                req.header.flags = *DEL_FLAGS;
                handle.clone().request(req).for_each(|message| {
                    if let NetlinkPayload::Error(ref err_message) = message.payload {
                        Err(ErrorKind::NetlinkError(err_message.clone()).into())
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
