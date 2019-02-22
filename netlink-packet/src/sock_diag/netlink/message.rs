use std::collections::HashMap;

use netlink_sys::constants::AF_NETLINK;

use crate::{
    constants::*,
    sock_diag::{
        netlink::{
            buffer::{Attr, RequestBuffer, ResponseBuffer, Show},
            raw::NDIAG_PROTO_ALL,
            Flags, Ring,
        },
        SkMemInfo,
    },
    DecodeError, Emitable, Parseable, ParseableParametrized,
};
lazy_static! {
    pub static ref PROTO_NAMES: HashMap<isize, &'static str> = {
        let mut m = HashMap::new();

        m.insert(NETLINK_ROUTE, "rtnl");
        m.insert(NETLINK_UNUSED, "unused");
        m.insert(NETLINK_USERSOCK, "usersock");
        m.insert(NETLINK_FIREWALL, "fw");
        m.insert(NETLINK_SOCK_DIAG, "tcpdiag");
        m.insert(NETLINK_NFLOG, "nflog");
        m.insert(NETLINK_XFRM, "xfrm");
        m.insert(NETLINK_SELINUX, "selinux");
        m.insert(NETLINK_ISCSI, "iscsi");
        m.insert(NETLINK_AUDIT, "audit");
        m.insert(NETLINK_FIB_LOOKUP, "fiblookup");
        m.insert(NETLINK_CONNECTOR, "connector");
        m.insert(NETLINK_NETFILTER, "nft");
        m.insert(NETLINK_IP6_FW, "ip6fw");
        m.insert(NETLINK_DNRTMSG, "dec-rt");
        m.insert(NETLINK_KOBJECT_UEVENT, "uevent");
        m.insert(NETLINK_GENERIC, "genl");
        m.insert(NETLINK_SCSITRANSPORT, "scsi-trans");
        m.insert(NETLINK_ECRYPTFS, "ecryptfs");
        m.insert(NETLINK_RDMA, "rdma");
        m.insert(NETLINK_CRYPTO, "crypto");
        m
    };
}

/// The request for `AF_NETLINK` sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Request {
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

impl Request {
    pub fn new() -> Self {
        Request::default()
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
            inode: 0,
            show: Show::empty(),
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

        req.set_family(AF_NETLINK as u8);
        req.set_protocol(NDIAG_PROTO_ALL);
        req.set_inode(self.inode);
        req.set_show(self.show);
        req.set_cookie(self.cookie)
    }
}

/// The response to a query for `AF_NETLINK` sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    /// The address family
    ///
    /// It should be set to `AF_NETLINK`.
    pub family: u8,
    /// This is set to one of `packet_type`.
    pub ty: u8,
    /// This is the protocol ID.
    pub proto: u8,

    pub state: u8,
    pub portid: i32,
    pub dst_portid: i32,
    pub dst_group: u32,
    /// This is the socket inode number.
    pub inode: u32,
    /// This is an opaque identifiers that could be used in subsequent queries.
    pub cookie: Option<u64>,
    /// socket attributes
    pub attrs: Vec<Attr>,
}

impl Response {
    pub fn rx_ring(&self) -> Option<&Ring> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::RxRing(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn tx_ring(&self) -> Option<&Ring> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::TxRing(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn groups(&self) -> Option<u32> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Groups(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn meminfo(&self) -> Option<&SkMemInfo> {
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

    pub fn flags(&self) -> Option<Flags> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Flags(value) = attr {
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
            .map(|(ty, payload)| payload.parse_with_param(ty))
            .collect::<Result<Vec<_>, DecodeError>>()?;

        Ok(Response {
            family: self.family(),
            ty: self.ty(),
            proto: self.protocol(),
            state: self.state(),
            portid: self.portid(),
            dst_portid: self.dst_portid(),
            dst_group: self.dst_group(),
            inode: self.inode(),
            cookie: self.cookie(),
            attrs,
        })
    }
}
