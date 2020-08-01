use super::{QDiscGetRequest, TrafficClassGetRequest};
use crate::Handle;

pub struct QDiscHandle(Handle);

impl QDiscHandle {
    pub fn new(handle: Handle) -> Self {
        QDiscHandle(handle)
    }

    /// Retrieve the list of qdisc (equivalent to `tc qdisc show`)
    pub fn get(&mut self) -> QDiscGetRequest {
        QDiscGetRequest::new(self.0.clone())
    }
}

pub struct TrafficClassHandle {
    handle: Handle,
    ifindex: i32,
}

impl TrafficClassHandle {
    pub fn new(handle: Handle, ifindex: i32) -> Self {
        TrafficClassHandle{handle, ifindex}
    }

    /// Retrieve the list of qdisc (equivalent to `tc qdisc show`)
    pub fn get(&mut self) -> TrafficClassGetRequest {
        TrafficClassGetRequest::new(self.handle.clone(), self.ifindex)
    }
}
