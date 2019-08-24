use crate::{
    rtnl::{
        route::{RouteBuffer, ROUTE_HEADER_LEN},
        traits::{Emitable, Parseable},
    },
    DecodeError,
};

/// Unknown route
pub const RTN_UNSPEC: u8 = 0;
/// A gateway or direct route
pub const RTN_UNICAST: u8 = 1;
/// A local interface route
pub const RTN_LOCAL: u8 = 2;
/// A local broadcast route (sent as a broadcast)
pub const RTN_BROADCAST: u8 = 3;
/// A local broadcast route (sent as a unicast)
pub const RTN_ANYCAST: u8 = 4;
/// A multicast route
pub const RTN_MULTICAST: u8 = 5;
/// A packet dropping route
pub const RTN_BLACKHOLE: u8 = 6;
/// An unreachable destination
pub const RTN_UNREACHABLE: u8 = 7;
/// A packet rejection route
pub const RTN_PROHIBIT: u8 = 8;
/// Continue routing lookup in another table
pub const RTN_THROW: u8 = 9;
/// A network address translation rule
pub const RTN_NAT: u8 = 10;
/// Refer to an external resolver (not implemented)
pub const RTN_XRESOLVE: u8 = 11;

/// Unknown
pub const RTPROT_UNSPEC: u8 = 0;
/// Route was learnt by an ICMP redirect
pub const RTPROT_REDIRECT: u8 = 1;
/// Route was learnt by the kernel
pub const RTPROT_KERNEL: u8 = 2;
/// Route was learnt during boot
pub const RTPROT_BOOT: u8 = 3;
/// Route was set statically
pub const RTPROT_STATIC: u8 = 4;
pub const RTPROT_GATED: u8 = 8;
pub const RTPROT_RA: u8 = 9;
pub const RTPROT_MRT: u8 = 10;
pub const RTPROT_ZEBRA: u8 = 11;
pub const RTPROT_BIRD: u8 = 12;
pub const RTPROT_DNROUTED: u8 = 13;
pub const RTPROT_XORP: u8 = 14;
pub const RTPROT_NTK: u8 = 15;
pub const RTPROT_DHCP: u8 = 16;
pub const RTPROT_MROUTED: u8 = 17;
pub const RTPROT_BABEL: u8 = 42;

/// Global route
pub const RT_SCOPE_UNIVERSE: u8 = 0;
/// Interior route in the local autonomous system
pub const RT_SCOPE_SITE: u8 = 200;
/// Route on this link
pub const RT_SCOPE_LINK: u8 = 253;
/// Route on the local host
pub const RT_SCOPE_HOST: u8 = 254;
/// Destination doesn't exist
pub const RT_SCOPE_NOWHERE: u8 = 255;

pub const RT_TABLE_UNSPEC: u8 = 0;
pub const RT_TABLE_COMPAT: u8 = 252;
pub const RT_TABLE_DEFAULT: u8 = 253;
pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;

pub const RTM_F_NOTIFY: u32 = 256;
pub const RTM_F_CLONED: u32 = 512;
pub const RTM_F_EQUALIZE: u32 = 1024;
pub const RTM_F_PREFIX: u32 = 2048;
pub const RTM_F_LOOKUP_TABLE: u32 = 4096;
pub const RTM_F_FIB_MATCH: u32 = 8192;

/// Route type
///
/// ```rust
/// # extern crate netlink_packet_route;
/// # use netlink_packet_route::rtnl::route::RouteKind;
/// #
/// # fn main() {
/// assert_eq!(RouteKind::default(), RouteKind::Unspec);
/// # }
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum RouteKind {
    /// Unknown route
    Unspec,
    /// A gateway or direct route
    Unicast,
    /// A local interface route
    Local,
    /// A local broadcast route (sent as a broadcast)
    Broadcast,
    /// A local broadcast route (sent as a unicast)
    Anycast,
    /// A multicast route
    Multicast,
    /// A packet dropping route
    Blackhole,
    /// An unreachable destination
    Unreachable,
    /// A packet rejection route
    Prohibit,
    /// Continue routing lookup in another table
    Throw,
    /// A network address translation rule
    Nat,
    /// Refer to an external resolver (not implemented)
    Xresolve,
    Unknown(u8),
}

impl Default for RouteKind {
    fn default() -> Self {
        RouteKind::Unspec
    }
}

impl From<RouteKind> for u8 {
    fn from(value: RouteKind) -> u8 {
        use self::RouteKind::*;
        match value {
            Unspec => RTN_UNSPEC,
            Unicast => RTN_UNICAST,
            Local => RTN_LOCAL,
            Broadcast => RTN_BROADCAST,
            Anycast => RTN_ANYCAST,
            Multicast => RTN_MULTICAST,
            Blackhole => RTN_BLACKHOLE,
            Unreachable => RTN_UNREACHABLE,
            Prohibit => RTN_PROHIBIT,
            Throw => RTN_THROW,
            Nat => RTN_NAT,
            Xresolve => RTN_XRESOLVE,
            Unknown(t) => t,
        }
    }
}

impl From<u8> for RouteKind {
    fn from(value: u8) -> RouteKind {
        use self::RouteKind::*;
        match value {
            RTN_UNSPEC => Unspec,
            RTN_UNICAST => Unicast,
            RTN_LOCAL => Local,
            RTN_BROADCAST => Broadcast,
            RTN_ANYCAST => Anycast,
            RTN_MULTICAST => Multicast,
            RTN_BLACKHOLE => Blackhole,
            RTN_UNREACHABLE => Unreachable,
            RTN_PROHIBIT => Prohibit,
            RTN_THROW => Throw,
            RTN_NAT => Nat,
            RTN_XRESOLVE => Xresolve,
            _ => Unknown(value),
        }
    }
}

/// Route origin.
///
/// ```rust
/// # extern crate netlink_packet_route;
/// # use netlink_packet_route::rtnl::route::RouteProtocol;
/// #
/// # fn main() {
/// assert_eq!(RouteProtocol::default(), RouteProtocol::Unspec);
/// # }
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum RouteProtocol {
    /// Unknown
    Unspec,
    /// Route was learnt by an ICMP redirect
    Redirect,
    /// Route was learnt by the kernel
    Kernel,
    /// Route was learnt during boot
    Boot,
    /// Route was set statically
    Static,
    Gated,
    Ra,
    Mrt,
    Zebra,
    Bird,
    Dnrouted,
    Xorp,
    Ntk,
    Dhcp,
    Mrouted,
    Babel,
    Unknown(u8),
}

impl Default for RouteProtocol {
    fn default() -> Self {
        RouteProtocol::Unspec
    }
}

impl From<RouteProtocol> for u8 {
    fn from(value: RouteProtocol) -> u8 {
        use self::RouteProtocol::*;
        match value {
            Unspec => RTPROT_UNSPEC,
            Redirect => RTPROT_REDIRECT,
            Kernel => RTPROT_KERNEL,
            Boot => RTPROT_BOOT,
            Static => RTPROT_STATIC,
            Gated => RTPROT_GATED,
            Ra => RTPROT_RA,
            Mrt => RTPROT_MRT,
            Zebra => RTPROT_ZEBRA,
            Bird => RTPROT_BIRD,
            Dnrouted => RTPROT_DNROUTED,
            Xorp => RTPROT_XORP,
            Ntk => RTPROT_NTK,
            Dhcp => RTPROT_DHCP,
            Mrouted => RTPROT_MROUTED,
            Babel => RTPROT_BABEL,
            Unknown(t) => t,
        }
    }
}

impl From<u8> for RouteProtocol {
    fn from(value: u8) -> RouteProtocol {
        use self::RouteProtocol::*;
        match value {
            RTPROT_UNSPEC => Unspec,
            RTPROT_REDIRECT => Redirect,
            RTPROT_KERNEL => Kernel,
            RTPROT_BOOT => Boot,
            RTPROT_STATIC => Static,
            RTPROT_GATED => Gated,
            RTPROT_RA => Ra,
            RTPROT_MRT => Mrt,
            RTPROT_ZEBRA => Zebra,
            RTPROT_BIRD => Bird,
            RTPROT_DNROUTED => Dnrouted,
            RTPROT_XORP => Xorp,
            RTPROT_NTK => Ntk,
            RTPROT_DHCP => Dhcp,
            RTPROT_MROUTED => Mrouted,
            RTPROT_BABEL => Babel,
            _ => Unknown(value),
        }
    }
}

/// Distance to the destination
///
/// ```rust
/// # extern crate netlink_packet_route;
/// # use netlink_packet_route::rtnl::route::RouteScope;
/// #
/// # fn main() {
/// assert_eq!(RouteScope::default(), RouteScope::Universe);
/// # }
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum RouteScope {
    /// Global route
    Universe,
    /// Interior route in the local autonomous system
    Site,
    /// Route on this link
    Link,
    /// Route on the local host
    Host,
    /// Destination doesn't exist
    Nowhere,
    Unknown(u8),
}

impl Default for RouteScope {
    fn default() -> Self {
        RouteScope::Universe
    }
}

impl From<RouteScope> for u8 {
    fn from(value: RouteScope) -> u8 {
        use self::RouteScope::*;
        match value {
            Universe => RT_SCOPE_UNIVERSE,
            Site => RT_SCOPE_SITE,
            Link => RT_SCOPE_LINK,
            Host => RT_SCOPE_HOST,
            Nowhere => RT_SCOPE_NOWHERE,
            Unknown(t) => t,
        }
    }
}

impl From<u8> for RouteScope {
    fn from(value: u8) -> RouteScope {
        use self::RouteScope::*;
        match value {
            RT_SCOPE_UNIVERSE => Universe,
            RT_SCOPE_SITE => Site,
            RT_SCOPE_LINK => Link,
            RT_SCOPE_HOST => Host,
            RT_SCOPE_NOWHERE => Nowhere,
            _ => Unknown(value),
        }
    }
}

/// Routing table
///
/// ```rust
/// # extern crate netlink_packet_route;
/// # use netlink_packet_route::rtnl::route::RouteTable;
/// #
/// # fn main() {
/// assert_eq!(RouteTable::default(), RouteTable::Unspec);
/// # }
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum RouteTable {
    Unspec,
    Compat,
    Default,
    Main,
    Local,
    Unknown(u8),
}

impl Default for RouteTable {
    fn default() -> Self {
        RouteTable::Unspec
    }
}

impl From<RouteTable> for u8 {
    fn from(value: RouteTable) -> u8 {
        use self::RouteTable::*;
        match value {
            Unspec => RT_TABLE_UNSPEC,
            Compat => RT_TABLE_COMPAT,
            Default => RT_TABLE_DEFAULT,
            Main => RT_TABLE_MAIN,
            Local => RT_TABLE_LOCAL,
            Unknown(t) => t,
        }
    }
}

impl From<u8> for RouteTable {
    fn from(value: u8) -> RouteTable {
        use self::RouteTable::*;
        match value {
            RT_TABLE_UNSPEC => Unspec,
            RT_TABLE_COMPAT => Compat,
            RT_TABLE_DEFAULT => Default,
            RT_TABLE_MAIN => Main,
            RT_TABLE_LOCAL => Local,
            _ => Unknown(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Default)]
pub struct RouteFlags(u32);

impl From<u32> for RouteFlags {
    fn from(value: u32) -> Self {
        RouteFlags(value)
    }
}

impl From<RouteFlags> for u32 {
    fn from(value: RouteFlags) -> Self {
        value.0
    }
}

impl RouteFlags {
    /// Create a new empty flags field (no flag is set)
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether the`RTM_F_NOTIFY` flag is set. If this flag is set and the route changes, a
    /// rtnetlink notification is sent to the user by the kernel.
    pub fn has_notify(self) -> bool {
        self.0 & RTM_F_NOTIFY == RTM_F_NOTIFY
    }

    /// Set the `RTM_F_NOTIFY` flag. If this flag is set and the route changes, a rtnetlink
    /// notification is sent to the user by the kernel.
    pub fn set_notify(&mut self) {
        self.0 |= RTM_F_NOTIFY
    }

    /// Check whether the`RTM_F_CLONED` flag is set. This flag is set if the route is cloned from
    /// another route.
    pub fn has_cloned(self) -> bool {
        self.0 & RTM_F_CLONED == RTM_F_CLONED
    }

    /// Set the`RTM_F_CLONED` flag. This flag is set if the route is cloned from another route.
    pub fn set_cloned(&mut self) {
        self.0 |= RTM_F_CLONED
    }

    /// Check whether the`RTM_F_EQUALIZE` flag is set.
    pub fn has_equalize(self) -> bool {
        self.0 & RTM_F_EQUALIZE == RTM_F_EQUALIZE
    }

    /// Set the`RTM_F_EQUALIZE` flag.
    pub fn set_equalize(&mut self) {
        self.0 |= RTM_F_EQUALIZE
    }

    /// Check whether the`RTM_F_PREFIX` flag is set.
    pub fn has_prefix(self) -> bool {
        self.0 & RTM_F_PREFIX == RTM_F_PREFIX
    }

    /// Set the`RTM_F_PREFIX` flag.
    pub fn set_prefix(&mut self) {
        self.0 |= RTM_F_PREFIX
    }

    /// Check whether the`RTM_F_LOOKUP_TABLE` flag is set.
    pub fn has_lookup_table(self) -> bool {
        self.0 & RTM_F_LOOKUP_TABLE == RTM_F_LOOKUP_TABLE
    }

    /// Set the`RTM_F_LOOKUP_TABLE` flag.
    pub fn set_lookup_table(&mut self) {
        self.0 |= RTM_F_LOOKUP_TABLE
    }

    /// Check whether the`RTM_F_FIB_MATCH` flag is set.
    pub fn has_fib_match(self) -> bool {
        self.0 & RTM_F_FIB_MATCH == RTM_F_FIB_MATCH
    }

    /// Set the`RTM_F_FIB_MATCH` flag.
    pub fn set_fib_match(&mut self) {
        self.0 |= RTM_F_FIB_MATCH
    }
}

/// High level representation of `RTM_GETROUTE`, `RTM_ADDROUTE`, `RTM_DELROUTE`
/// messages headers.
///
/// These headers have the following structure:
///
/// ```no_rust
/// 0                8                16              24               32
/// +----------------+----------------+----------------+----------------+
/// | address family | dest. length   | source length  |      tos       |
/// +----------------+----------------+----------------+----------------+
/// |     table      |   protocol     |      scope     | type (kind)    |
/// +----------------+----------------+----------------+----------------+
/// |                               flags                               |
/// +----------------+----------------+----------------+----------------+
/// ```
///
/// # Example
///
/// ```rust
/// extern crate netlink_packet_route;
/// use netlink_packet_route::rtnl::route::{RouteHeader, RouteFlags, RouteProtocol, RouteTable, RouteScope, RouteKind};
///
/// fn main() {
///     let mut hdr = RouteHeader::new();
///     assert_eq!(hdr.address_family, 0u8);
///     assert_eq!(hdr.destination_length, 0u8);
///     assert_eq!(hdr.source_length, 0u8);
///     assert_eq!(hdr.tos, 0u8);
///     assert_eq!(hdr.table, RouteTable::Unspec);
///     assert_eq!(hdr.protocol, RouteProtocol::Unspec);
///     assert_eq!(hdr.scope, RouteScope::Universe);
///     assert_eq!(hdr.kind, RouteKind::Unspec);
///     assert_eq!(u32::from(hdr.flags), 0u32);
///
///     hdr.destination_length = 8;
///     hdr.table = RouteTable::Default;
///     hdr.protocol = RouteProtocol::Kernel;
///     hdr.scope = RouteScope::Nowhere;
///
///     // ...
/// }
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct RouteHeader {
    /// Address family of the route
    pub address_family: u8,
    /// Length of destination
    pub destination_length: u8,
    /// Length of source
    pub source_length: u8,
    /// TOS filter
    pub tos: u8,

    /// The routing table ID
    pub table: RouteTable,
    /// The routing protocol
    pub protocol: RouteProtocol,
    /// Distance to the destination
    pub scope: RouteScope,
    /// Route type
    pub kind: RouteKind,

    pub flags: RouteFlags,
}

impl RouteHeader {
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<RouteHeader> for RouteBuffer<&'a T> {
    fn parse(&self) -> Result<RouteHeader, DecodeError> {
        Ok(RouteHeader {
            address_family: self.address_family(),
            destination_length: self.destination_length(),
            source_length: self.source_length(),
            tos: self.tos(),
            table: self.table(),
            protocol: self.protocol(),
            scope: self.scope(),
            kind: self.kind(),
            flags: self.flags(),
        })
    }
}

impl Emitable for RouteHeader {
    fn buffer_len(&self) -> usize {
        ROUTE_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = RouteBuffer::new(buffer);
        buffer.set_address_family(self.address_family);
        buffer.set_destination_length(self.destination_length);
        buffer.set_source_length(self.source_length);
        buffer.set_tos(self.tos);
        buffer.set_table(self.table);
        buffer.set_protocol(self.protocol);
        buffer.set_scope(self.scope);
        buffer.set_kind(self.kind);
        buffer.set_flags(self.flags);
    }
}
