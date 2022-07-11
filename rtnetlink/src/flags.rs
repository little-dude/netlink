bitflags::bitflags! {
    pub struct GetFlags: u16 {
        /// Must be set on all request messages (typically from user
        /// space to kernel space)
        ///
        /// **This flag is set by default**
        const REQUEST = 1;
        ///  Indicates the message is part of a multipart message
        ///  terminated by NLMSG_DONE
        const MULTIPART = 2;
        /// Request for an acknowledgment on success. Typical
        /// direction of request is from user space (CPC) to kernel
        /// space (FEC).
        const ACK = 4;
        /// Echo this request. Typical direction of request is from
        /// user space (CPC) to kernel space (FEC).
        const ECHO = 8;
        /// Return the complete table instead of a single entry.
        const ROOT = 256;
        /// Return all entries matching criteria passed in message
        /// content.
        const MATCH = 512;
        /// Return an atomic snapshot of the table. Requires
        /// `CAP_NET_ADMIN` capability or a effective UID of 0.
        const ATOMIC = 1024;
        /// Equivalent to `ROOT|MATCH`.
        const DUMP = 768;
    }
}

impl GetFlags {
    /// Create new `GetFlags` with only `GetFlags::REQUEST`.
    pub fn new() -> Self {
        GetFlags::REQUEST
    }
}

impl Default for GetFlags {
    /// Create new `GetFlags` with only `GetFlags::REQUEST`.
    fn default() -> Self {
        Self::new()
    }
}

bitflags::bitflags! {
    pub struct NewFlags: u16 {
        /// Must be set on all request messages (typically from user
        /// space to kernel space).
        ///
        /// **This flag is set by default**
        const REQUEST = 1;
        ///  Indicates the message is part of a multipart message
        ///  terminated by NLMSG_DONE
        const MULTIPART = 2;
        /// Request for an acknowledgment on success. Typical
        /// direction of request is from user space (CPC) to kernel
        /// space (FEC).
        ///
        /// **This flag is set by default**
        const ACK = 4;
        /// Echo this request. Typical direction of request is from
        /// user space (CPC) to kernel space (FEC).
        const ECHO = 8;
        /// Replace existing matching object.
        const REPLACE = 256;
        /// Don't replace if the object already exists.
        ///
        /// This flag is not set by default but can is pretty commonly
        /// used.
        const EXCL = 512;
        /// Create object if it doesn't already exist.
        ///
        /// **This flag is set by default**
        const CREATE = 1024;
        /// Add to the end of the object list.
        const APPEND = 2048;
        /// Do not delete recursively
        const NONREC = 256;
    }
}

impl NewFlags {
    /// Create new `NewFlags` with `REQUEST | ACK | CREATE` set.
    pub fn new() -> Self {
        Self::REQUEST | Self::ACK | Self::CREATE
    }
}

impl Default for NewFlags {
    /// Create new `NewFlags` with `REQUEST | ACK | CREATE` set.
    fn default() -> Self {
        Self::new()
    }
}

bitflags::bitflags! {
    pub struct DelFlags: u16 {
        /// Must be set on all request messages (typically from user
        /// space to kernel space)
        ///
        /// **This flag is set by default**
        const REQUEST = 1;
        ///  Indicates the message is part of a multipart message
        ///  terminated by NLMSG_DONE
        const MULTIPART = 2;
        /// Request for an acknowledgment on success. Typical
        /// direction of request is from user space (CPC) to kernel
        /// space (FEC).
        ///
        /// **This flag is set by default**
        const ACK = 4;
        /// Echo this request. Typical direction of request is from
        /// user space (CPC) to kernel space (FEC).
        const ECHO = 8;
        /// Do not delete recursively
        const NONREC = 256;
    }
}

impl DelFlags {
    /// Create a new `DelFlags` with `REQUEST | ACK` set
    pub fn new() -> Self {
        Self::REQUEST | Self::ACK
    }
}

impl Default for DelFlags {
    /// Create a new `DelFlags` with `REQUEST | ACK` set
    fn default() -> Self {
        Self::new()
    }
}
