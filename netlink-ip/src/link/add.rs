use futures::Future;

use netlink_sys::constants::{IFF_UP, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use netlink_sys::rtnl::{
    LinkFlags, LinkInfo, LinkInfoData, LinkInfoKind, LinkMessage, LinkNla, Message, RtnlMessage,
};
use netlink_sys::NetlinkFlags;

use connection::ConnectionHandle;
use errors::NetlinkIpError;

use Stream2Ack;

lazy_static! {
    // Flags for `ip link add`
    static ref ADD_FLAGS: NetlinkFlags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
}

pub struct AddRequest {
    handle: ConnectionHandle,
    message: LinkMessage,
}

impl AddRequest {
    pub(crate) fn new(handle: ConnectionHandle) -> Self {
        let mut message = LinkMessage::new();
        message.header_mut();
        AddRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl Future<Item = (), Error = NetlinkIpError> {
        let AddRequest {
            mut handle,
            message,
        } = self;
        let mut req = Message::from(RtnlMessage::NewLink(message));
        req.header_mut().set_flags(*ADD_FLAGS);
        Stream2Ack::new(handle.request(req))
    }

    /// Return a mutable reference to the request
    pub fn message_mut(&mut self) -> &mut LinkMessage {
        &mut self.message
    }

    /// Add a dummy link
    pub fn dummy(self, name: String) -> Self {
        self.name(name).link_info(LinkInfoKind::Dummy, None).up()
    }

    /// Create a veth pair
    pub fn veth(self, name: String, peer_name: String) -> Self {
        let mut peer = LinkMessage::new();
        peer.nlas_mut().push(LinkNla::IfName(peer_name));

        self.name(name)
            .link_info(LinkInfoKind::Veth, Some(LinkInfoData::Veth(peer)))
            .up()
    }

    fn up(mut self) -> Self {
        self.message_mut()
            .header_mut()
            .set_flags(LinkFlags::from(IFF_UP))
            .set_change_mask(LinkFlags::from(IFF_UP));
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
        self.message.append_nla(LinkNla::IfName(name));
        self
    }

    fn append_nla(mut self, nla: LinkNla) -> Self {
        self.message.nlas_mut().push(nla);
        self
    }
}
