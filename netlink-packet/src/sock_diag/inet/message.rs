use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use try_from::TryFrom;

use netlink_sys::constants::{AF_INET, AF_INET6};

use crate::sock_diag::{
    inet::buffer::{Attr, RequestBuffer, ResponseBuffer},
    Extension, Extensions, MemInfo, Shutdown, SkMemInfo, TcpInfo, TcpState, TcpStates, Timer,
};
use crate::{DecodeError, Emitable, Parseable, ParseableParametrized};

/// The socket ID object
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SockId {
    /// The source address and port.
    pub src: Option<SocketAddr>,
    /// The destination address and port.
    pub dst: Option<SocketAddr>,
    /// The interface number the socket is bound to.
    pub interface: u32,
    /// This is an array of opaque identifiers
    /// that could be used along with other fields of this structure
    /// to specify an individual socket.
    pub cookie: Option<u64>,
}

/// The request for IPv4 and IPv6 sockets
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// This should be set to either AF_INET or AF_INET6 for IPv4 or IPv6 sockets respectively.
    pub family: u8,
    /// This should be set to one of IPPROTO_TCP, IPPROTO_UDP, or IPPROTO_UDPLITE.
    pub protocol: u8,
    /// This is a set of flags defining what kind of extended information to report.
    ///
    /// Each requested kind of information is reported back as a netlink attribute.
    pub extensions: Extensions,
    /// This is a bit mask that defines a filter of socket states.
    ///
    /// Only those sockets whose states are in this mask will be reported.
    /// Ignored when querying for an individual socket.
    pub states: TcpStates,
    /// This is a socket ID object that is used in dump requests,
    /// in queries about individual sockets, and is reported back in each response.
    ///
    /// Unlike UNIX domain sockets, IPv4 and IPv6 sockets are identified using addresses and ports.
    pub id: SockId,
}

pub fn inet(protocol: u8) -> Request {
    Request::new(AF_INET as u8, protocol)
}

pub fn inet6(protocol: u8) -> Request {
    Request::new(AF_INET6 as u8, protocol)
}

impl Deref for Request {
    type Target = SockId;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl DerefMut for Request {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.id
    }
}

impl Request {
    pub fn new(family: u8, protocol: u8) -> Request {
        Request {
            family,
            protocol,
            extensions: Extensions::empty(),
            states: TcpStates::all(),
            id: SockId::default(),
        }
    }

    pub fn with_states(mut self, states: TcpStates) -> Self {
        self.states.insert(states);
        self
    }

    pub fn without_states(mut self, states: TcpStates) -> Self {
        self.states.remove(states);
        self
    }

    pub fn with_extensions(mut self, exts: Extensions) -> Self {
        self.extensions.insert(exts);
        self
    }

    pub fn with_state(self, state: TcpState) -> Self {
        self.with_states(state.into())
    }

    pub fn without_state(self, state: TcpState) -> Self {
        self.without_states(state.into())
    }

    pub fn with_extension(self, ext: Extension) -> Self {
        self.with_extensions(ext.into())
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
        req.set_extensions(self.extensions);
        req.set_states(self.states);

        let mut id = req.id_mut();

        if let Some(addr) = self.id.src.as_ref() {
            id.set_src_addr(addr)
        }
        if let Some(addr) = self.id.dst.as_ref() {
            id.set_dst_addr(addr)
        }
        id.set_interface(self.id.interface);
        id.set_cookie(self.id.cookie);
    }
}

/// The response to a query for IPv4 or IPv6 sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    /// This should be set to either AF_INET or AF_INET6 for IPv4 or IPv6 sockets respectively.
    pub family: u8,
    /// This is the socket states.
    pub state: u8,
    /// For TCP sockets, this field describes the type of timer
    /// that is currently active for the socket.
    pub timer: Option<Timer>,
    /// The socket ID object.
    pub id: SockId,
    /// For TCP sockets that have an active timer, this field describes its expiration time.
    pub expires: Option<Duration>,
    /// For listening sockets: the number of pending connections.
    /// For other sockets: the amount of data in the incoming queue.
    pub rqueue: u32,
    /// For listening sockets: the backlog length.
    /// For other sockets: the amount of memory available for sending.
    pub wqueue: u32,
    /// This is the socket owner UID.
    pub uid: u32,
    /// This is the socket inode number.
    pub inode: u32,
    pub attrs: Vec<Attr>,
}

impl Deref for Response {
    type Target = SockId;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl Response {
    /// the memory information of the socket.
    pub fn meminfo(&self) -> Option<&MemInfo> {
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

    /// the TCP information
    pub fn tcp_info(&self) -> Option<&TcpInfo> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Info(ref value) = attr {
                    Some(&**value)
                } else {
                    None
                }
            })
            .next()
    }

    /// the congestion control algorithm used
    pub fn conf(&self) -> Option<&str> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Conf(ref value) = attr {
                    Some(value.as_str())
                } else {
                    None
                }
            })
            .next()
    }

    /// the TOS of the socket.
    pub fn tos(&self) -> Option<u8> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Tos(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    /// the TClass of the socket.
    pub fn tclass(&self) -> Option<u8> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::TClass(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    /// socket memory information
    pub fn socket_mem_info(&self) -> Option<&SkMemInfo> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::SkMemInfo(ref value) = attr {
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

    /// The protocol
    pub fn protocol(&self) -> Option<u8> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Protocol(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    /// The socket is IPv6 only
    pub fn ipv6_only(&self) -> Option<bool> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::SkV6Only(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    /// The mark of the socket.
    pub fn mark(&self) -> Option<u32> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Mark(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    /// The class ID of the socket.
    pub fn class_id(&self) -> Option<u32> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::ClassId(value) = attr {
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
        let family = self.family();
        let id = self.id();

        let (src, dst) = match u16::from(family) {
            AF_INET => {
                let sip = id.src_ipv4();
                let sport = id.sport();
                let dip = id.dst_ipv4();
                let dport = id.dport();

                (
                    if sip.is_unspecified() && sport == 0 {
                        None
                    } else {
                        Some(SocketAddrV4::new(sip, sport).into())
                    },
                    if dip.is_unspecified() && dport == 0 {
                        None
                    } else {
                        Some(SocketAddrV4::new(dip, dport).into())
                    },
                )
            }
            AF_INET6 => {
                let sip = id.src_ipv6();
                let sport = id.sport();
                let dip = id.dst_ipv6();
                let dport = id.dport();

                (
                    if sip.is_unspecified() && sport == 0 {
                        None
                    } else {
                        Some(SocketAddrV6::new(sip, sport, 0, 0).into())
                    },
                    if dip.is_unspecified() && dport == 0 {
                        None
                    } else {
                        Some(SocketAddrV6::new(dip, dport, 0, 0).into())
                    },
                )
            }
            _ => (None, None),
        };

        let attrs = self
            .attrs()
            .map(|(ty, payload)| {
                Extension::try_from(ty).and_then(|ty| payload.parse_with_param(ty))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;

        Ok(Response {
            family,
            state: self.state(),
            timer: self.timer(),
            id: SockId {
                src,
                dst,
                interface: id.interface(),
                cookie: id.cookie(),
            },
            expires: self.expires(),
            rqueue: self.rqueue(),
            wqueue: self.wqueue(),
            uid: self.uid(),
            inode: self.inode(),
            attrs,
        })
    }
}
