// SPDX-License-Identifier: MIT

use crate::{Nl80211Handle, Nl80211InterfaceGetRequest};

pub struct Nl80211InterfaceHandle(Nl80211Handle);

impl Nl80211InterfaceHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Nl80211InterfaceHandle(handle)
    }

    /// Retrieve the wireless interfaces
    /// (equivalent to `iw dev`)
    pub fn get(&mut self) -> Nl80211InterfaceGetRequest {
        Nl80211InterfaceGetRequest::new(self.0.clone())
    }
}
