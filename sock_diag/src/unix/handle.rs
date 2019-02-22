use super::List;
use crate::Handle;

pub struct UnixHandle(Handle);

impl UnixHandle {
    pub fn new(handle: Handle) -> Self {
        UnixHandle(handle)
    }

    /// Retrieve the list of sockets (equivalent to `ss --unix`)
    pub fn list(&mut self) -> List {
        List::new(self.0.clone())
    }
}
