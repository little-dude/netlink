use try_from::TryFrom;

use netlink_sys::constants::AF_UNIX;

use crate::sock_diag::{
    unix::{
        buffer::{Attr, RequestBuffer, ResponseBuffer},
        Attribute, RqLen, Show, State, States, Vfs,
    },
    Shutdown, SkMemInfo,
};
use crate::{DecodeError, Emitable, Parseable, ParseableParametrized};

/// The request for UNIX domain sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Request {
    /// The address family
    ///
    /// It should be set to `AF_UNIX`.
    pub family: u8,
    /// It should be set to 0
    pub protocol: u8,
    /// This is a bit mask that defines a filter of sockets states.
    ///
    /// Only those sockets whose states are in this mask will be reported.
    /// Ignored when querying for an individual socket.
    pub states: States,
    /// This is an inode number when querying for an individual socket.
    ///
    /// Ignored when querying for a list of sockets.
    pub inode: u32,
    /// This is a set of flags defining what kind of information to report.
    ///
    /// Each requested kind of information is reported back as a netlink attribute
    pub show: Show,
    /// This is an opaque identifiers that could be used to specify an individual socket.
    pub cookie: Option<u64>,
}

pub fn unix() -> Request {
    Request::new()
}

impl Request {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_states(mut self, states: States) -> Self {
        self.states.insert(states);
        self
    }

    pub fn without_states(mut self, states: States) -> Self {
        self.states.remove(states);
        self
    }

    pub fn with_state(self, state: State) -> Self {
        self.with_states(state.into())
    }

    pub fn without_state(self, state: State) -> Self {
        self.without_states(state.into())
    }

    pub fn with_inode(mut self, inode: u32) -> Self {
        self.inode = inode;
        self
    }

    pub fn with_show(mut self, show: Show) -> Self {
        self.show.insert(show);
        self
    }

    pub fn with_cookie(mut self, cookie: u64) -> Self {
        self.cookie = Some(cookie);
        self
    }
}

impl Default for Request {
    fn default() -> Self {
        Request {
            family: AF_UNIX as u8,
            protocol: 0,
            states: States::all(),
            inode: 0,
            show: Show::NAME | Show::PEER,
            cookie: None,
        }
    }
}

impl Emitable for Request {
    fn buffer_len(&self) -> usize {
        RequestBuffer::<()>::len()
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut req = RequestBuffer::new(buf);

        req.set_family(self.family);
        req.set_protocol(self.protocol);
        req.set_states(self.states);
        req.set_inode(self.inode);
        req.set_show(self.show);
        req.set_cookie(self.cookie)
    }
}

/// The response to a query for UNIX domain sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    /// The address family
    ///
    /// It should be set to `AF_UNIX`.
    pub family: u8,
    /// This is set to one of `SOCK_PACKET`, `SOCK_STREAM`, or `SOCK_SEQPACKET`.
    pub ty: u8,
    /// This is set to one of `LISTEN` or `ESTABLISHED`.
    pub state: State,
    /// This is the socket inode number.
    pub inode: u32,
    /// This is an opaque identifiers that could be used in subsequent queries.
    pub cookie: Option<u64>,
    /// socket attributes
    pub attrs: Vec<Attr>,
}

impl Response {
    /// name (not path)
    pub fn name(&self) -> Option<&str> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Name(ref value) = attr {
                    Some(value.as_str())
                } else {
                    None
                }
            })
            .next()
    }

    /// VFS inode info
    pub fn vfs(&self) -> Option<&Vfs> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Vfs(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    /// peer socket info
    pub fn peer(&self) -> Option<u32> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Peer(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    /// pending connections
    pub fn icons(&self) -> Option<&[u32]> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Icons(value) = attr {
                    Some(value.as_slice())
                } else {
                    None
                }
            })
            .next()
    }

    /// skb receive queue len
    pub fn rqlen(&self) -> Option<&RqLen> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::RecvQueueLen(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    /// memory info of a socket
    pub fn socket_mem_info(&self) -> Option<&SkMemInfo> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::MemInfo(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    /// shutdown states
    pub fn shutdown(&self) -> Option<Shutdown> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Shutdown(ref value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }
}

impl<T: AsRef<[u8]>> Parseable<Response> for ResponseBuffer<T> {
    fn parse(&self) -> Result<Response, DecodeError> {
        let attrs = self
            .attrs()
            .map(|(ty, payload)| {
                Attribute::try_from(ty).and_then(|ty| payload.parse_with_param(ty))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;

        Ok(Response {
            family: self.family(),
            ty: self.ty(),
            state: self.state()?,
            inode: self.inode(),
            cookie: self.cookie(),
            attrs,
        })
    }
}
