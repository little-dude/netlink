use std::os::unix::io::RawFd;

use futures::{Future, Stream};

use netlink_packet_core::{
    header::flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST},
    NetlinkFlags, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    link::{nlas::LinkNla, LinkFlags, LinkMessage, IFF_UP},
    RtnlMessage,
};

use crate::{Error, ErrorKind, Handle};

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
        message.header.index = index;
        LinkSetRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let LinkSetRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::SetLink(message));
        req.header.flags = *SET_FLAGS;
        handle.request(req).for_each(|message| {
            if let NetlinkPayload::Error(err) = message.payload {
                Err(ErrorKind::NetlinkError(err).into())
            } else {
                Ok(())
            }
        })
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }

    /// Attach the link to a bridge (its _master_). This is equivalent to `ip link set LINK master
    /// BRIDGE`. To succeed, both the bridge and the link that is being attached must be UP.
    pub fn master(mut self, master_index: u32) -> Self {
        self.message.nlas.push(LinkNla::Master(master_index));
        self
    }

    /// Set the link with the given index up (equivalent to `ip link set dev DEV up`)
    pub fn up(mut self) -> Self {
        self.message.header.flags = LinkFlags::from(IFF_UP);
        self.message.header.change_mask = LinkFlags::from(IFF_UP);
        self
    }

    /// Set the link with the given index down (equivalent to `ip link set dev DEV down`)
    pub fn down(mut self) -> Self {
        self.message.header.change_mask = LinkFlags::from(IFF_UP);
        self
    }

    /// Set the name of the link with the given index (equivalent to `ip link set DEV name NAME`)
    pub fn name(mut self, name: String) -> Self {
        self.message.nlas.push(LinkNla::IfName(name));
        self
    }

    /// Set the mtu of the link with the given index (equivalent to `ip link set DEV mtu MTU`)
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.message.nlas.push(LinkNla::Mtu(mtu));
        self
    }

    /// Set the hardware address of the link with the given index (equivalent to `ip link set DEV address ADDRESS`)
    pub fn address(mut self, address: Vec<u8>) -> Self {
        self.message.nlas.push(LinkNla::Address(address));
        self
    }

    /// Move this network device into the network namespace of the process with the given `pid`.
    pub fn setns_by_pid(mut self, pid: u32) -> Self {
        self.message.nlas.push(LinkNla::NetNsPid(pid));
        self
    }

    /// Move this network device into the network namespace corresponding to the given file
    /// descriptor.
    pub fn setns_by_fd(mut self, fd: RawFd) -> Self {
        self.message.nlas.push(LinkNla::NetNsFd(fd));
        self
    }
}
