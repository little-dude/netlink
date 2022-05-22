// SPDX-License-Identifier: MIT

use crate::{MptcpPathManagerAddressGetRequest, MptcpPathManagerHandle};

pub struct MptcpPathManagerAddressHandle(MptcpPathManagerHandle);

impl MptcpPathManagerAddressHandle {
    pub fn new(handle: MptcpPathManagerHandle) -> Self {
        MptcpPathManagerAddressHandle(handle)
    }

    /// Retrieve the multipath-TCP  addresses
    /// (equivalent to `ip mptcp endpoint show`)
    pub fn get(&mut self) -> MptcpPathManagerAddressGetRequest {
        MptcpPathManagerAddressGetRequest::new(self.0.clone())
    }
}
