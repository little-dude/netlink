use super::List;
use crate::Handle;

pub struct NetlinkHandle(Handle);

impl NetlinkHandle {
    pub fn new(handle: Handle) -> Self {
        NetlinkHandle(handle)
    }

    /// Retrieve the list of sockets (equivalent to `ss --family=netlink`)
    pub fn list(&mut self) -> List {
        List::new(self.0.clone())
    }
}
