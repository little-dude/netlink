use connection::ConnectionHandle;

use super::{AddRequest, DelRequest, GetRequest, SetRequest};

pub struct LinkHandle(ConnectionHandle);

impl LinkHandle {
    pub fn new(handle: ConnectionHandle) -> Self {
        LinkHandle(handle)
    }

    pub fn set(&self, index: u32) -> SetRequest {
        SetRequest::new(self.0.clone(), index)
    }

    pub fn add(&self) -> AddRequest {
        AddRequest::new(self.0.clone())
    }

    pub fn del(&mut self, index: u32) -> DelRequest {
        DelRequest::new(self.0.clone(), index)
    }

    /// Retrieve the list of links (equivalent to `ip link show`)
    pub fn get(&mut self) -> GetRequest {
        GetRequest::new(self.0.clone())
    }
}
