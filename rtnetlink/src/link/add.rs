use futures::{Future, Stream};

use netlink_packet_core::{
    header::flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST},
    NetlinkFlags, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    link::{
        nlas::{LinkInfo, LinkInfoData, LinkInfoKind, LinkInfoVlan, LinkNla, VethInfoNla},
        LinkFlags, LinkMessage, IFF_UP,
    },
    RtnlMessage,
};

use crate::{Error, ErrorKind, Handle};

lazy_static! {
    // Flags for `ip link add`
    static ref ADD_FLAGS: NetlinkFlags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

/// A request to create a new link. This is equivalent to the `ip link add` commands.
///
/// A few methods for common actions (creating a veth pair, creating a vlan interface, etc.) are
/// provided, but custom requests can be made using the [`message_mut()`](#method.message_mut)
/// accessor.
pub struct LinkAddRequest {
    handle: Handle,
    message: LinkMessage,
}

impl LinkAddRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        LinkAddRequest {
            handle,
            message: LinkMessage::new(),
        }
    }

    /// Execute the request.
    pub fn execute(self) -> impl Future<Item = (), Error = Error> {
        let LinkAddRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::NewLink(message));
        req.header.flags = *ADD_FLAGS;
        handle.request(req).for_each(|message| {
            if let NetlinkPayload::Error(err) = message.payload {
                Err(ErrorKind::NetlinkError(err).into())
            } else {
                Ok(())
            }
        })
    }

    /// Return a mutable reference to the request message.
    ///
    /// # Example
    ///
    /// Let's say we want to create a vlan interface on a link with id 6. By default, the
    /// [`vlan()`](#method.vlan) method would create a request with the `IFF_UP` link set, so that the
    /// interface is up after creation. If we want to create a interface tha tis down by default we
    /// could do:
    ///
    /// ```rust,no_run
    /// extern crate futures;
    /// extern crate rtnetlink;
    /// extern crate tokio_core;
    ///
    /// use std::thread::spawn;
    ///
    /// use futures::Future;
    /// use tokio_core::reactor::Core;
    ///
    /// use rtnetlink::new_connection;
    ///
    /// fn main() {
    ///     let (connection, handle) = new_connection().unwrap();
    ///     spawn(move || Core::new().unwrap().run(connection));
    ///     let vlan_id = 100;
    ///     let link_id = 6;
    ///     let mut request = handle.link().add().vlan("my-vlan-itf".into(), link_id, vlan_id);
    ///     // unset the IFF_UP flag before sending the request
    ///     request.message_mut().header.flags.unset_up();
    ///     request.message_mut().header.change_mask.unset_up();
    ///     // send the request
    ///     request.execute().wait().unwrap();
    /// }
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }

    /// Create a dummy link.
    /// This is equivalent to `ip link add NAME type dummy`.
    pub fn dummy(self, name: String) -> Self {
        self.name(name).link_info(LinkInfoKind::Dummy, None).up()
    }

    /// Create a veth pair.
    /// This is equivalent to `ip link add NAME1 type veth peer name NAME2`.
    pub fn veth(self, name: String, peer_name: String) -> Self {
        // NOTE: `name` is the name of the peer in the netlink message (ie the link created via the
        // VethInfoNla::Peer attribute, and `peer_name` is the name in the main netlink message.
        // This is a bit weird, but it's all hidden from the user.

        let mut peer = LinkMessage::new();
        // FIXME: we get a -107 (ENOTCONN) (???) when trying to set `name` up.
        // peer.header.flags = LinkFlags::from(IFF_UP);
        // peer.header.change_mask = LinkFlags::from(IFF_UP);
        peer.nlas.push(LinkNla::IfName(name));
        let link_info_data = LinkInfoData::Veth(VethInfoNla::Peer(peer));
        self.name(peer_name)
            .up() // iproute2 does not set this one up
            .link_info(LinkInfoKind::Veth, Some(link_info_data))
    }

    /// Create VLAN on a link.
    /// This is equivalent to `ip link add link LINK name NAME type vlan id VLAN_ID`,
    /// but instead of specifying a link name (`LINK`), we specify a link index.
    pub fn vlan(self, name: String, index: u32, vlan_id: u16) -> Self {
        self.name(name)
            .link_info(
                LinkInfoKind::Vlan,
                Some(LinkInfoData::Vlan(vec![LinkInfoVlan::Id(vlan_id)])),
            )
            .append_nla(LinkNla::Link(index))
            .up()
    }

    /// Create a new bridge.
    /// This is equivalent to `ip link add link NAME type bridge`.
    pub fn bridge(self, name: String) -> Self {
        self.name(name.clone())
            .link_info(LinkInfoKind::Bridge, None)
            .append_nla(LinkNla::IfName(name))
    }

    fn up(mut self) -> Self {
        self.message.header.flags = LinkFlags::from(IFF_UP);
        self.message.header.change_mask = LinkFlags::from(IFF_UP);
        self
    }

    fn link_info(self, kind: LinkInfoKind, data: Option<LinkInfoData>) -> Self {
        let mut link_info_nlas = vec![LinkInfo::Kind(kind)];
        if let Some(data) = data {
            link_info_nlas.push(LinkInfo::Data(data));
        }
        self.append_nla(LinkNla::LinkInfo(link_info_nlas))
    }

    fn name(mut self, name: String) -> Self {
        self.message.nlas.push(LinkNla::IfName(name));
        self
    }

    fn append_nla(mut self, nla: LinkNla) -> Self {
        self.message.nlas.push(nla);
        self
    }
}
