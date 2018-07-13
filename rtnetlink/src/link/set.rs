use eui48::MacAddress;
use futures::{Future, Stream};

use packet::constants::{IFF_UP, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use packet::{LinkFlags, LinkMessage, LinkNla, NetlinkFlags, NetlinkMessage, RtnlMessage};

use {Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip link set`
    static ref SET_FLAGS: NetlinkFlags =
        NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct LinkSetRequest {
    handle: Handle,
    message: LinkMessage,
}

impl LinkSetRequest {
    pub(crate) fn new(handle: Handle, index: u32) -> Self {
        let mut message = LinkMessage::new();
        message.header_mut().set_index(index);
        LinkSetRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let LinkSetRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::SetLink(message));
        req.header_mut().set_flags(*SET_FLAGS);
        handle.request(req).for_each(|message| {
            if message.is_error() {
                Err(ErrorKind::NetlinkError(message).into())
            } else {
                Ok(())
            }
        })
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }

    /// Set the link with the given index up (equivalent to `ip link set dev DEV up`)
    pub fn up(mut self) -> Self {
        self.message
            .header_mut()
            .set_flags(LinkFlags::from(IFF_UP))
            .set_change_mask(LinkFlags::from(IFF_UP));
        self
    }

    /// Set the link with the given index down (equivalent to `ip link set dev DEV down`)
    pub fn down(mut self) -> Self {
        self.message
            .header_mut()
            .set_change_mask(LinkFlags::from(IFF_UP));
        self
    }

    /// Set the name of the link with the given index (equivalent to `ip link set DEV name NAME`)
    pub fn name(mut self, name: String) -> Self {
        self.message.append_nla(LinkNla::IfName(name));
        self
    }

    /// Set the mtu of the link with the given index (equivalent to `ip link set DEV mtu MTU`)
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.message.append_nla(LinkNla::Mtu(mtu));
        self
    }

    /// Set the hardware address of the link with the given index (equivalent to `ip link set DEV address ADDRESS`)
    pub fn address(mut self, address: MacAddress) -> Self {
        self.message
            .append_nla(LinkNla::Address(Vec::from(address.as_bytes())));
        self
    }
}
