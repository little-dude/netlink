use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use failure::ResultExt;
use try_from::TryFrom;

use netlink_sys::constants::{AF_INET, AF_INET6, AF_UNIX};

use crate::sock_diag::{
    buffer::{
        Extensions, InetDiagAttr, InetDiagMsgBuffer, InetDiagReqV2Buffer, Show, TcpStates, Timer,
        UnixDiagAttr, UnixDiagMsgBuffer, UnixDiagReqBuffer, UnixStates,
    },
    sock_diag::SOCK_DIAG_BY_FAMILY,
    Attribute, Extension, TcpState, UnixState,
};
use crate::{DecodeError, Emitable, Parseable, ParseableParametrized};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SockDiagMessage {
    InetDiag(InetDiagRequest),
    InetSocks(InetDiagResponse),
    UnixDiag(UnixDiagRequest),
    UnixSocks(UnixDiagResponse),
}

impl Emitable for SockDiagMessage {
    fn buffer_len(&self) -> usize {
        use SockDiagMessage::*;

        match self {
            InetDiag(ref req) => req.buffer_len(),
            UnixDiag(ref req) => req.buffer_len(),
            _ => unimplemented!(),
        }
    }

    fn emit(&self, buf: &mut [u8]) {
        use SockDiagMessage::*;

        match self {
            InetDiag(ref req) => req.emit(buf),
            UnixDiag(ref req) => req.emit(buf),
            _ => unimplemented!(),
        }
    }
}

impl SockDiagMessage {
    pub(crate) fn parse(message_type: u16, buffer: &[u8]) -> Result<Self, DecodeError> {
        match message_type {
            SOCK_DIAG_BY_FAMILY if !buffer.is_empty() => {
                match u16::from(*buffer.first().unwrap()) {
                    AF_INET | AF_INET6 => Ok(SockDiagMessage::InetSocks(
                        InetDiagMsgBuffer::new_checked(buffer)
                            .context("failed to parse SOCK_DIAG_BY_FAMILY message")?
                            .parse()
                            .context("failed to parse SOCK_DIAG_BY_FAMILY message")?,
                    )),
                    AF_UNIX => Ok(SockDiagMessage::UnixSocks(
                        UnixDiagMsgBuffer::new_checked(buffer)
                            .context("failed to parse SOCK_DIAG_BY_FAMILY message")?
                            .parse()
                            .context("failed to parse SOCK_DIAG_BY_FAMILY message")?,
                    )),
                    family => Err(format!("Unknown message family: {}", family).into()),
                }
            }
            _ => Err(format!("Unknown message type: {}", message_type).into()),
        }
    }

    pub fn message_type(&self) -> u16 {
        SOCK_DIAG_BY_FAMILY
    }
}

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
pub struct InetDiagRequest {
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

pub fn inet(protocol: u8) -> InetDiagRequest {
    InetDiagRequest::new(AF_INET as u8, protocol)
}

pub fn inet6(protocol: u8) -> InetDiagRequest {
    InetDiagRequest::new(AF_INET6 as u8, protocol)
}

pub fn unix() -> UnixDiagRequest {
    UnixDiagRequest::new()
}

impl InetDiagRequest {
    pub fn new(family: u8, protocol: u8) -> InetDiagRequest {
        InetDiagRequest {
            family,
            protocol,
            extensions: Extensions::empty(),
            states: TcpStates::all(),
            id: SockId::default(),
        }
    }

    pub fn with_state(mut self, state: TcpState) -> Self {
        self.states
            .insert(TcpStates::from_bits_truncate(1 << state as usize));
        self
    }

    pub fn without_state(mut self, state: TcpState) -> Self {
        self.states
            .remove(TcpStates::from_bits_truncate(1 << state as usize));
        self
    }

    pub fn with_extension(mut self, ext: Extension) -> Self {
        self.extensions
            .insert(Extensions::from_bits_truncate(1 << (ext as usize - 1)));
        self
    }
}

impl Emitable for InetDiagRequest {
    fn buffer_len(&self) -> usize {
        InetDiagReqV2Buffer::<()>::len()
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut req = InetDiagReqV2Buffer::new(buf);

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
pub struct InetDiagResponse {
    /// This should be set to either AF_INET or AF_INET6 for IPv4 or IPv6 sockets respectively.
    pub family: u8,
    /// This is the socket states.
    pub state: TcpState,
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
    pub attrs: Vec<InetDiagAttr>,
}

impl<T: AsRef<[u8]>> Parseable<InetDiagResponse> for InetDiagMsgBuffer<T> {
    fn parse(&self) -> Result<InetDiagResponse, DecodeError> {
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

        Ok(InetDiagResponse {
            family,
            state: self.state()?,
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

/// The request for UNIX domain sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnixDiagRequest {
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
    pub states: UnixStates,
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

impl UnixDiagRequest {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for UnixDiagRequest {
    fn default() -> Self {
        UnixDiagRequest {
            family: AF_UNIX as u8,
            protocol: 0,
            states: UnixStates::all(),
            inode: 0,
            show: Show::NAME | Show::PEER,
            cookie: None,
        }
    }
}

impl Emitable for UnixDiagRequest {
    fn buffer_len(&self) -> usize {
        UnixDiagReqBuffer::<()>::len()
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut req = UnixDiagReqBuffer::new(buf);

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
pub struct UnixDiagResponse {
    /// The address family
    ///
    /// It should be set to `AF_UNIX`.
    pub family: u8,
    /// This is set to one of `SOCK_PACKET`, `SOCK_STREAM`, or `SOCK_SEQPACKET`.
    pub ty: u8,
    /// This is set to one of `LISTEN` or `ESTABLISHED`.
    pub state: UnixState,
    /// This is the socket inode number.
    pub inode: u32,
    /// This is an opaque identifiers that could be used in subsequent queries.
    pub cookie: Option<u64>,
    pub attrs: Vec<UnixDiagAttr>,
}

impl<T: AsRef<[u8]>> Parseable<UnixDiagResponse> for UnixDiagMsgBuffer<T> {
    fn parse(&self) -> Result<UnixDiagResponse, DecodeError> {
        let attrs = self
            .attrs()
            .map(|(ty, payload)| {
                Attribute::try_from(ty).and_then(|ty| payload.parse_with_param(ty))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;

        Ok(UnixDiagResponse {
            family: self.family(),
            ty: self.ty(),
            state: self.state()?,
            inode: self.inode(),
            cookie: self.cookie(),
            attrs,
        })
    }
}
