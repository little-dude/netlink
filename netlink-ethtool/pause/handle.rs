use crate::{EthtoolHandle, PauseGetRequest};

pub struct PauseHandle(EthtoolHandle);

impl PauseHandle {
    pub fn new(handle: EthtoolHandle) -> Self {
        PauseHandle(handle)
    }

    /// Retrieve the pause setting of a interface (equivalent to `ethtool -a eth1`)
    pub fn get(&mut self, iface_name: &str) -> PauseGetRequest {
        PauseGetRequest::new(self.0.clone(), iface_name)
    }
}
