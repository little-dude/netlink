use std::ops::{Deref, DerefMut};

use failure::Error;
use futures::Stream;

use crate::packet::{
    inet::{Expr, Extensions, Request, Response, TcpStates},
    NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use crate::{ErrorKind, Handle};

pub struct List {
    handle: Handle,
    request: Request,
}

impl Deref for List {
    type Target = Request;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl DerefMut for List {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.request
    }
}

impl List {
    pub(crate) fn new(handle: Handle, family: u8, protocol: u8) -> Self {
        List {
            handle,
            request: Request::new(family, protocol),
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

    pub fn with_expr(mut self, expr: Option<Expr>) -> Self {
        self.request.expr = expr;
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl Stream<Item = Response, Error = Error> {
        let List {
            mut handle,
            request,
        } = self;

        let mut req = NetlinkMessage::from(SockDiagMessage::InetDiag(request));

        req.header.flags.set_dump().set_request();

        handle.request(req).and_then(move |msg| {
            let (header, payload) = msg.into_parts();
            if let NetlinkPayload::SockDiag(SockDiagMessage::InetSock(msg)) = payload {
                Ok(msg)
            } else {
                Err(ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into())
            }
        })
    }
}
