use futures::stream::StreamExt;
use std::net::IpAddr;

use netlink_packet_route::{
    nlas::route::Nla, NetlinkMessage, NetlinkPayload, RouteKind, RouteMessage, RouteProtocol,
    RouteScope, RouteTable, RtnlMessage, AF_INET, AF_INET6, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL,
    NLM_F_REQUEST,
};

use crate::{Error, ErrorKind, Handle};

fn addr_octets(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    }
}

/// A request to create a new route. This is equivalent to the `ip route add` commands.
pub struct RouteAddRequest {
    handle: Handle,
    message: RouteMessage,
}

impl RouteAddRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let mut message = RouteMessage::default();

        message.header.table = RouteTable::Main;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteKind::Unicast;

        RouteAddRequest { handle, message }
    }

    fn set_addr_family(&mut self, addr: &IpAddr) {
        match addr {
            IpAddr::V4(_)
                if self.message.header.address_family == 0
                    || self.message.header.address_family == AF_INET as u8 =>
            {
                self.message.header.address_family = AF_INET as u8;
            }
            IpAddr::V6(_)
                if self.message.header.address_family == 0
                    || self.message.header.address_family == AF_INET6 as u8 =>
            {
                self.message.header.address_family = AF_INET6 as u8;
            }
            _ => panic!("All addresses within a routing request must be either IPv4 or IPv6."),
        };
    }

    /// Sets the input interface index.
    pub fn input_interface(mut self, index: u32) -> Self {
        self.message.nlas.push(Nla::Iif(index));
        self
    }

    /// Sets the output interface index.
    pub fn output_interface(mut self, index: u32) -> Self {
        self.message.nlas.push(Nla::Oif(index));
        self
    }

    /// Sets the source address prefix.
    ///
    /// # Panics
    /// Panics when IPv4 and IPv6 addresses are mixed in the same request.
    pub fn src_prefix(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.set_addr_family(&addr);
        self.message.header.source_length = prefix_len;
        self.message.nlas.push(Nla::Source(addr_octets(&addr)));
        self
    }

    /// Sets the destination address prefix.
    ///
    /// # Panics
    /// Panics when IPv4 and IPv6 addresses are mixed in the same request.
    pub fn dst_prefix(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.set_addr_family(&addr);
        self.message.header.destination_length = prefix_len;
        self.message.nlas.push(Nla::Destination(addr_octets(&addr)));
        self
    }

    /// Sets the gateway (via) address.
    ///
    /// # Panics
    /// Panics when IPv4 and IPv6 addresses are mixed in the same request.
    pub fn gateway(mut self, addr: IpAddr) -> Self {
        self.set_addr_family(&addr);
        self.message.nlas.push(Nla::Gateway(addr_octets(&addr)));
        self
    }

    /// Sets the route table.
    ///
    /// Default is main route table.
    pub fn table(mut self, table: RouteTable) -> Self {
        self.message.header.table = table;
        self
    }

    /// Sets the route protocol.
    ///
    /// Default is static route protocol.
    pub fn protocol(mut self, protocol: RouteProtocol) -> Self {
        self.message.header.protocol = protocol;
        self
    }

    /// Sets the route scope.
    ///
    /// Default is universe route scope.
    pub fn scope(mut self, scope: RouteScope) -> Self {
        self.message.header.scope = scope;
        self
    }

    /// Sets the route kind.
    ///
    /// Default is unicast route kind.
    pub fn kind(mut self, kind: RouteKind) -> Self {
        self.message.header.kind = kind;
        self
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let RouteAddRequest {
            mut handle,
            message,
        } = self;
        let mut req = NetlinkMessage::from(RtnlMessage::NewRoute(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            if let NetlinkPayload::Error(err) = message.payload {
                return Err(ErrorKind::NetlinkError(err).into());
            }
        }
        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut RouteMessage {
        &mut self.message
    }
}
