mod flags;
pub use self::flags::*;

mod link_layer_type;
pub use self::link_layer_type::*;

use crate::{
    link::{LinkBuffer, LINK_HEADER_LEN},
    traits::{Emitable, Parseable},
    DecodeError,
};

/// High level representation of `RTM_GETLINK`, `RTM_SETLINK`, `RTM_NEWLINK` and `RTM_DELLINK`
/// messages headers.
///
/// These headers have the following structure:
///
/// ```no_rust
/// 0                8                16              24               32
/// +----------------+----------------+----------------+----------------+
/// |interface family|    reserved    |         link layer type         |
/// +----------------+----------------+----------------+----------------+
/// |                             link index                            |
/// +----------------+----------------+----------------+----------------+
/// |                               flags                               |
/// +----------------+----------------+----------------+----------------+
/// |                            change mask                            |
/// +----------------+----------------+----------------+----------------+
/// ```
///
/// `LinkHeader` exposes all these fields except for the "reserved" one.
///
/// # Example
///
/// ```rust
/// extern crate netlink_packet_core;
/// extern crate netlink_packet_route;
///
/// use netlink_packet_route::link::{LinkHeader, LinkFlags, LinkLayerType, IFF_UP};
/// fn main() {
///     let mut hdr = LinkHeader::new();
///     assert_eq!(hdr.interface_family, 0u8);
///     assert_eq!(hdr.link_layer_type, LinkLayerType::Ether);
///     assert_eq!(hdr.flags, LinkFlags::new());
///     assert_eq!(hdr.change_mask, LinkFlags::new());
///
///     let flags = LinkFlags::from(IFF_UP);
///     hdr.flags = flags;
///     hdr.change_mask = flags;
///     hdr.link_layer_type = LinkLayerType::IpGre;
/// }
/// ```
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkHeader {
    pub interface_family: u8,
    pub index: u32,
    pub link_layer_type: LinkLayerType,
    pub flags: LinkFlags,
    pub change_mask: LinkFlags,
}

impl Default for LinkHeader {
    fn default() -> Self {
        LinkHeader::new()
    }
}

impl LinkHeader {
    /// Create a new `LinkHeader`:
    ///
    /// - interface family defaults to `AF_UNSPEC` (0)
    /// - the link layer type defaults to `ARPHRD_ETHER` ([`LinkLayerType::Ether`](enum.LinkLayerType.html))
    /// - the linx index defaults to 0
    /// - the flags default to 0 ([`LinkFlags::new()`](struct.LinkFlags.html#method.new))
    /// - the change master default to 0 ([`LinkFlags::new()`](struct.LinkFlags.html#method.new))
    pub fn new() -> Self {
        LinkHeader {
            interface_family: 0, // AF_UNSPEC
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::new(),
            change_mask: LinkFlags::new(),
            index: 0,
        }
    }
}

impl Emitable for LinkHeader {
    fn buffer_len(&self) -> usize {
        LINK_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = LinkBuffer::new(buffer);
        packet.set_interface_family(self.interface_family);
        packet.set_link_index(self.index);
        packet.set_change_mask(self.change_mask);
        packet.set_link_layer_type(self.link_layer_type);
        packet.set_flags(self.flags);
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkHeader> for LinkBuffer<T> {
    fn parse(&self) -> Result<LinkHeader, DecodeError> {
        Ok(LinkHeader {
            interface_family: self.interface_family(),
            link_layer_type: self.link_layer_type(),
            index: self.link_index(),
            change_mask: self.change_mask(),
            flags: self.flags(),
        })
    }
}
