use crate::errors::{Error, ErrorKind};
use crate::packet::{LinkFlags, LinkLayerType, LinkMessage, LinkNla, LinkState};
use eui48::MacAddress;

mod handle;
pub use self::handle::*;

mod add;
pub use self::add::*;

mod del;
pub use self::del::*;

mod get;
pub use self::get::*;

mod set;
pub use self::set::*;

#[derive(Clone, Debug, Default)]
pub struct Link {
    // These attributes are common to all the links, since they are part of the
    // RTM_{GET,SET,DEL,NEW}LINK header.
    /// Address family. Defaults to 0 (`AF_UNSPEC`).
    address_family: u8,
    /// Link index. Defaults to 0.
    index: u32,
    /// Link layer type. Defaults to `LinkLayerType::Ether` (`ARPHRD_ETHER`).
    link_layer_type: LinkLayerType,
    /// Link flags. Defaults to 0 (no flag set).
    flags: LinkFlags,
    /// Change mask. Defaults to 0 (no flag set).
    change_mask: LinkFlags,

    // These attributes are common and useful, but are not guaranteed to be part of the
    // RTM_{GET,SET,DEL,NEW}LINK messages, so they are options.
    name: Option<String>,
    mtu: Option<u32>,
    tx_queue_length: Option<u32>,
    address: Option<MacAddress>,
    parent_index: Option<u32>,
    master_index: Option<u32>,
    alias: Option<String>,
    promiscuous_mode: Option<bool>,
    operational_state: Option<LinkState>,
    attributes: Vec<LinkNla>,
}

impl Link {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn address_family(&self) -> u8 {
        self.address_family
    }

    pub fn address_family_mut(&mut self) -> &mut u8 {
        &mut self.address_family
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn index_mut(&mut self) -> &mut u32 {
        &mut self.index
    }

    pub fn link_layer_type(&self) -> LinkLayerType {
        self.link_layer_type
    }

    pub fn link_layer_type_mut(&mut self) -> &mut LinkLayerType {
        &mut self.link_layer_type
    }

    pub fn flags(&self) -> LinkFlags {
        self.flags
    }

    pub fn flags_mut(&mut self) -> &mut LinkFlags {
        &mut self.flags
    }

    pub fn change_mask(&self) -> LinkFlags {
        self.change_mask
    }

    pub fn change_mask_mut(&mut self) -> &mut LinkFlags {
        &mut self.change_mask
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(String::as_ref)
    }

    pub fn name_mut(&mut self) -> Option<&mut String> {
        self.name.as_mut()
    }

    pub fn mtu(&self) -> Option<u32> {
        self.mtu.as_ref().cloned()
    }

    pub fn mtu_mut(&mut self) -> Option<&mut u32> {
        self.mtu.as_mut()
    }

    pub fn tx_queue_length(&self) -> Option<u32> {
        self.tx_queue_length.as_ref().cloned()
    }

    pub fn tx_queue_length_mut(&mut self) -> Option<&mut u32> {
        self.tx_queue_length.as_mut()
    }

    pub fn address(&self) -> Option<&MacAddress> {
        self.address.as_ref()
    }

    pub fn address_mut(&mut self) -> Option<&mut MacAddress> {
        self.address.as_mut()
    }

    pub fn parent_index(&self) -> Option<u32> {
        self.parent_index.as_ref().cloned()
    }

    pub fn parent_index_mut(&mut self) -> Option<&mut u32> {
        self.parent_index.as_mut()
    }

    pub fn master_index(&self) -> Option<u32> {
        self.master_index.as_ref().cloned()
    }

    pub fn master_index_mut(&mut self) -> Option<&mut u32> {
        self.master_index.as_mut()
    }

    pub fn alias(&self) -> Option<&str> {
        self.alias.as_ref().map(String::as_ref)
    }

    pub fn alias_mut(&mut self) -> Option<&mut String> {
        self.alias.as_mut()
    }

    pub fn promiscuous_mode(&self) -> Option<bool> {
        self.promiscuous_mode.as_ref().cloned()
    }

    pub fn promiscuous_mode_mut(&mut self) -> Option<&mut bool> {
        self.promiscuous_mode.as_mut()
    }

    pub fn operational_state(&self) -> Option<LinkState> {
        self.operational_state.as_ref().cloned()
    }

    pub fn operational_state_mut(&mut self) -> Option<&mut LinkState> {
        self.operational_state.as_mut()
    }

    pub fn attributes(&self) -> &[LinkNla] {
        self.attributes.as_slice()
    }

    pub fn attributes_mut(&mut self) -> &mut [LinkNla] {
        self.attributes.as_mut_slice()
    }

    pub fn set_address_family(&mut self, value: u8) -> &mut Self {
        self.address_family = value;
        self
    }

    pub fn set_index(&mut self, value: u32) -> &mut Self {
        self.index = value;
        self
    }

    pub fn set_link_layer_type(&mut self, value: LinkLayerType) -> &mut Self {
        self.link_layer_type = value;
        self
    }

    pub fn set_flags(&mut self, value: LinkFlags) -> &mut Self {
        self.flags = value;
        self
    }

    pub fn set_change_mask(&mut self, value: LinkFlags) -> &mut Self {
        self.change_mask = value;
        self
    }

    pub fn set_name(&mut self, value: String) -> &mut Self {
        self.name = Some(value);
        self
    }

    pub fn set_mtu(&mut self, value: u32) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    pub fn set_tx_queue_length(&mut self, value: u32) -> &mut Self {
        self.tx_queue_length = Some(value);
        self
    }

    pub fn set_address(&mut self, value: MacAddress) -> &mut Self {
        self.address = Some(value);
        self
    }

    pub fn set_parent_index(&mut self, value: u32) -> &mut Self {
        self.parent_index = Some(value);
        self
    }

    pub fn set_master_index(&mut self, value: u32) -> &mut Self {
        self.master_index = Some(value);
        self
    }

    pub fn set_alias(&mut self, value: String) -> &mut Self {
        self.alias = Some(value);
        self
    }

    pub fn set_promiscuous_mode(&mut self, value: bool) -> &mut Self {
        self.promiscuous_mode = Some(value);
        self
    }

    pub fn set_operational_state(&mut self, value: LinkState) -> &mut Self {
        self.operational_state = Some(value);
        self
    }

    pub fn set_attributes(&mut self, value: Vec<LinkNla>) -> &mut Self {
        self.attributes = value;
        self
    }

    pub fn add_attribute(&mut self, value: LinkNla) -> &mut Self {
        self.attributes.push(value);
        self
    }

    pub fn from_link_message(value: LinkMessage) -> Result<Self, Error> {
        let (header, mut nlas) = value.into_parts();
        let mut link = Link::default();
        link.set_index(header.index())
            .set_address_family(header.address_family())
            .set_link_layer_type(header.link_layer_type())
            .set_flags(header.flags())
            .set_change_mask(header.change_mask());
        for nla in nlas.drain(..) {
            let _ = match nla {
                LinkNla::Address(bytes) => {
                    // FIXME: we should check the length first. Also we should not assume MAC addresses.
                    link.set_address(
                        MacAddress::from_bytes(&bytes[..])
                            .map_err(|_| ErrorKind::InvalidHardwareAddress(bytes.clone()))?,
                    )
                }
                LinkNla::IfName(name) => link.set_name(name),
                LinkNla::IfAlias(alias) => link.set_alias(alias),
                LinkNla::Mtu(mtu) => link.set_mtu(mtu),
                LinkNla::Master(index) => link.set_master_index(index),
                LinkNla::TxQueueLen(length) => link.set_tx_queue_length(length),
                LinkNla::Promiscuity(promisc) => link.set_promiscuous_mode(promisc != 0),
                LinkNla::OperState(state) => link.set_operational_state(state),
                _ => link.add_attribute(nla),
            };
        }
        Ok(link)
    }
}
