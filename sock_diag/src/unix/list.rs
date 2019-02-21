use std::ops::{Deref, DerefMut};

use failure::Error;
use futures::Stream;

use crate::packet::{
    unix::{Request, Response, Show, States},
    NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use crate::{ErrorKind, Handle};

pub struct ListRequest {
    handle: Handle,
    request: Request,
}

impl Deref for ListRequest {
    type Target = Request;

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
    pub(crate) fn new(handle: Handle) -> Self {
        ListRequest {
            handle,
            request: Request::new(),
        }
    }

    pub fn with_states(mut self, states: States) -> Self {
        self.request.states.insert(states);
        self
    }

    pub fn without_states(mut self, states: States) -> Self {
        self.request.states.remove(states);
        self
    }

    pub fn with_show(mut self, show: Show) -> Self {
        self.request.show.insert(show);
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl Stream<Item = Response, Error = Error> {
        let ListRequest {
            mut handle,
            request,
        } = self;

        let mut req = NetlinkMessage::from(SockDiagMessage::UnixDiag(request));

        req.header.flags.set_dump().set_request();

        handle.request(req).and_then(move |msg| {
            let (header, payload) = msg.into_parts();
            if let NetlinkPayload::SockDiag(SockDiagMessage::UnixSock(msg)) = payload {
                Ok(msg)
            } else {
                Err(ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into())
            }
        })
    }
}
