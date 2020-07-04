use super::QDiscGetRequest;
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
