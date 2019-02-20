use std::ops::{Deref, DerefMut};

use failure::Error;
use futures::Stream;

use crate::packet::{
    Extensions, InetDiagRequest, InetDiagResponse, NetlinkMessage, NetlinkPayload, SockDiagMessage,
    TcpStates,
};
use crate::{ErrorKind, Handle};

pub struct ListRequest {
    handle: Handle,
    request: InetDiagRequest,
}

impl Deref for ListRequest {
    type Target = InetDiagRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl DerefMut for ListRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.request
    }
}

impl ListRequest {
    pub(crate) fn new(handle: Handle, family: u8, protocol: u8) -> Self {
        ListRequest {
            handle,
            request: InetDiagRequest::new(family, protocol),
        }
    }

    pub fn with_states(mut self, states: TcpStates) -> Self {
        self.request.states.insert(states);
        self
    }

    pub fn without_states(mut self, states: TcpStates) -> Self {
        self.request.states.remove(states);
        self
    }

    pub fn with_extensions(mut self, ext: Extensions) -> Self {
        self.request.extensions.insert(ext);
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl Stream<Item = InetDiagResponse, Error = Error> {
        let ListRequest {
            mut handle,
            request,
        } = self;

        let mut req = NetlinkMessage::from(SockDiagMessage::InetDiag(request));

        req.header.flags.set_dump().set_request();

        handle.request(req).and_then(move |msg| {
            let (header, payload) = msg.into_parts();
            if let NetlinkPayload::SockDiag(SockDiagMessage::InetSocks(msg)) = payload {
                Ok(msg)
            } else {
                Err(ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into())
            }
        })
    }
}
