use super::ListRequest;
use crate::Handle;

pub struct InetHandle(Handle);

impl InetHandle {
    pub fn new(handle: Handle) -> Self {
        InetHandle(handle)
    }

    /// Retrieve the list of sockets (equivalent to `ss -4` or `ss -6`)
    pub fn list(&mut self, family: u8, protocol: u8) -> ListRequest {
        ListRequest::new(self.0.clone(), family, protocol)
    }
}
