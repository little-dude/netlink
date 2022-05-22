// SPDX-License-Identifier: MIT

use crate::{MptcpPathManagerHandle, MptcpPathManagerLimitsGetRequest};

pub struct MptcpPathManagerLimitsHandle(MptcpPathManagerHandle);

impl MptcpPathManagerLimitsHandle {
    pub fn new(handle: MptcpPathManagerHandle) -> Self {
        MptcpPathManagerLimitsHandle(handle)
    }

    /// Retrieve the multipath-TCP  addresses
    /// (equivalent to `ip mptcp endpoint show`)
    pub fn get(&mut self) -> MptcpPathManagerLimitsGetRequest {
        MptcpPathManagerLimitsGetRequest::new(self.0.clone())
    }
}
