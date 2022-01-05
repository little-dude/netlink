mod allowedip;
mod device;
mod peer;

pub use allowedip::WgAllowedIpAttrs;
pub use device::WgDeviceAttrs;
pub use peer::WgPeerAttrs;

use netlink_packet_utils::{Emitable, nla::Nla};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NestedSlice<'a, T: Nla>(&'a [T]);
impl<'a, T: Nla> Nla for NestedSlice<'a, T> {
    fn value_len(&self) -> usize {
        self.0.buffer_len()
    }

    fn kind(&self) -> u16 {
        0
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.emit(buffer);
    }

    fn is_nested(&self) -> bool {
        true
    }
}
