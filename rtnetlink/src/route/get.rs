use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};

use netlink_packet_route::{
    NetlinkMessage, NetlinkPayload, RouteKind, RouteMessage, RouteProtocol, RouteScope, RouteTable,
    RtnlMessage, AF_INET, AF_INET6, NLM_F_DUMP, NLM_F_REQUEST,
};

use crate::{Error, ErrorKind, Handle};

pub struct RouteGetRequest {
    handle: Handle,
    message: RouteMessage,
}

/// Internet Protocol (IP) version.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd)]
pub enum IpVersion {
    /// IPv4
    V4,
    /// IPv6
    V6,
}

impl RouteGetRequest {
    pub(crate) fn new(handle: Handle, ip_version: IpVersion) -> Self {
        let mut message = RouteMessage::default();
        message.header.address_family = match ip_version {
            IpVersion::V4 => AF_INET as u8,
            IpVersion::V6 => AF_INET6 as u8,
        };
        message.header.destination_length = 0;
        message.header.source_length = 0;
        message.header.table = RouteTable::Default;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteKind::Unicast;

        RouteGetRequest { handle, message }
    }

    pub fn message_mut(&mut self) -> &mut RouteMessage {
        &mut self.message
    }

    pub fn execute(self) -> impl TryStream<Ok = RouteMessage, Error = Error> {
        let RouteGetRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::GetRoute(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                let (header, payload) = msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(RtnlMessage::NewRoute(msg)) => Ok(msg),
                    NetlinkPayload::Error(err) => Err(ErrorKind::NetlinkError(err).into()),
                    _ => Err(
                        ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into(),
                    ),
                }
            })),
            Err(e) => Either::Right(future::err::<RouteMessage, Error>(e).into_stream()),
        }
    }
}
