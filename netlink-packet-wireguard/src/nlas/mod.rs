// SPDX-License-Identifier: MIT

mod allowedip;
mod device;
mod peer;

pub use allowedip::WgAllowedIpAttrs;
pub use device::WgDeviceAttrs;
pub use peer::{WgAllowedIp, WgPeer, WgPeerAttrs};
