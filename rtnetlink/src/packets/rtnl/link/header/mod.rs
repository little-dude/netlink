mod flags;
pub use self::flags::*;
mod link_layer_type;
pub use self::link_layer_type::*;

use super::{LinkBuffer, LINK_HEADER_LEN};
use {Emitable, Parseable, Result};

/// High level representation of `RTM_GETLINK`, `RTM_SETLINK`, `RTM_NEWLINK` and `RTM_DELLING`
/// messages headers.
///
/// These headers have the following structure:
///
/// ```no_rust
/// 0                8                16              24               32
/// +----------------+----------------+----------------+----------------+
/// | address family |    reserved    |         link layer type         |
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
/// extern crate rtnetlink;
/// use rtnetlink::{LinkHeader, LinkFlags, LinkLayerType};
/// use rtnetlink::constants::IFF_UP;
///
/// fn main() {
///     let mut hdr = LinkHeader::new();
///     assert_eq!(hdr.address_family(), 0u8);
///     assert_eq!(hdr.link_layer_type(), LinkLayerType::Ether);
///     assert_eq!(hdr.flags(), LinkFlags::new());
///     assert_eq!(hdr.change_mask(), LinkFlags::new());
///
///     let flags = LinkFlags::from(IFF_UP);
///     hdr.set_flags(flags)
///        .set_change_mask(flags)
///        .set_link_layer_type(LinkLayerType::IpGre);
///
///     assert_eq!(hdr.address_family(), 0u8);
///     assert_eq!(hdr.link_layer_type(), LinkLayerType::IpGre);
///     assert!(hdr.flags().is_up());
///     assert!(hdr.change_mask().is_up());
/// }
/// ```
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkHeader {
    address_family: u8,
    index: u32,
    link_layer_type: LinkLayerType,
    flags: LinkFlags,
    change_mask: LinkFlags,
}

impl Default for LinkHeader {
    fn default() -> Self {
        LinkHeader::new()
    }
}

impl LinkHeader {
    /// Create a new `LinkHeader`:
    ///
    /// - address family defaults to `AF_UNSPEC` (0)
    /// - the link layer type defaults to `ARPHRD_ETHER` ([`LinkLayerType::Ether`](enum.LinkLayerType.html))
    /// - the linx index defaults to 0
    /// - the flags default to 0 ([`LinkFlags::new()`](struct.LinkFlags.html#method.new))
    /// - the change master default to 0 ([`LinkFlags::new()`](struct.LinkFlags.html#method.new))
    pub fn new() -> Self {
        LinkHeader {
            address_family: 0, // AF_UNSPEC
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::new(),
            change_mask: LinkFlags::new(),
            index: 0,
        }
    }

    /// Get the address family
    pub fn address_family(&self) -> u8 {
        self.address_family
    }

    /// Get a mutable reference to the address family value
    pub fn address_family_mut(&mut self) -> &mut u8 {
        &mut self.address_family
    }

    /// Set the address family value, and return a mutable reference to this `LinkHeader`, so that
    /// other `set_` methods can be called on it.
    pub fn set_address_family(&mut self, value: u8) -> &mut Self {
        self.address_family = value;
        self
    }

    /// Get the link index
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get a mutable reference to the link index value
    pub fn index_mut(&mut self) -> &mut u32 {
        &mut self.index
    }

    /// Set the link index value, and return a mutable reference to this `LinkHeader`, so that
    /// other `set_` methods can be called on it.
    pub fn set_index(&mut self, value: u32) -> &mut Self {
        self.index = value;
        self
    }

    /// Get the link layer type
    pub fn link_layer_type(&self) -> LinkLayerType {
        self.link_layer_type
    }

    /// Get a mutable reference to the link layer type value
    pub fn link_layer_type_mut(&mut self) -> &mut LinkLayerType {
        &mut self.link_layer_type
    }

    /// Set the link layer type value, and return a mutable reference to this `LinkHeader`, so that
    /// other `set_` methods can be called on it.
    pub fn set_link_layer_type(&mut self, value: LinkLayerType) -> &mut Self {
        self.link_layer_type = value;
        self
    }

    /// Get the flags
    pub fn flags(&self) -> LinkFlags {
        self.flags
    }

    /// Get a mutable reference to the flags value
    pub fn flags_mut(&mut self) -> &mut LinkFlags {
        &mut self.flags
    }

    /// Set the flags value, and return a mutable reference to this `LinkHeader`, so that
    /// other `set_` methods can be called on it.
    pub fn set_flags(&mut self, value: LinkFlags) -> &mut Self {
        self.flags = value;
        self
    }

    /// Get the change mask
    pub fn change_mask(&self) -> LinkFlags {
        self.change_mask
    }

    /// Get a mutable reference to the change mask value
    pub fn change_mask_mut(&mut self) -> &mut LinkFlags {
        &mut self.change_mask
    }

    /// Set the change mask value, and return a mutable reference to this `LinkHeader`, so that
    /// other `set_` methods can be called on it.
    pub fn set_change_mask(&mut self, value: LinkFlags) -> &mut Self {
        self.change_mask = value;
        self
    }
}

impl Emitable for LinkHeader {
    fn buffer_len(&self) -> usize {
        LINK_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = LinkBuffer::new(buffer);
        packet.set_address_family(self.address_family);
        packet.set_link_index(self.index);
        packet.set_change_mask(self.change_mask);
        packet.set_link_layer_type(self.link_layer_type);
        packet.set_flags(self.flags);
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkHeader> for LinkBuffer<T> {
    fn parse(&self) -> Result<LinkHeader> {
        Ok(LinkHeader {
            address_family: self.address_family(),
            link_layer_type: self.link_layer_type(),
            index: self.link_index(),
            change_mask: self.change_mask(),
            flags: self.flags(),
        })
    }
}
