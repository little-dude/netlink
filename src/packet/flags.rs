use constants;
use libc;

// Standard flag bits
// =====================================

/// Must be set on all request messages (typically from user space to kernel space)
pub const NLM_F_REQUEST: u16 = libc::NLM_F_REQUEST as u16;
///  Indicates the message is part of a multipart message terminated by NLMSG_DONE
pub const NLM_MULTIPART: u16 = libc::NLM_F_MULTI as u16;
/// Request for an acknowledgment on success. Typical direction of request is from user space
/// (CPC) to kernel space (FEC).
pub const NLM_F_ACK: u16 = libc::NLM_F_ACK as u16;
/// Echo this request.  Typical direction of request is from user space (CPC) to kernel space
/// (FEC).
pub const NLM_F_ECHO: u16 = libc::NLM_F_ECHO as u16;
/// Dump was inconsistent due to sequence change
pub const NLM_F_DUMP_INTR: u16 = libc::NLM_F_DUMP_INTR as u16;
/// Dump was filtered as requested
pub const NLM_F_DUMP_FILTERED: u16 = libc::NLM_F_DUMP_FILTERED as u16;

// Additional flag bits for GET requests
// =====================================

/// Return the complete table instead of a single entry.
pub const NLM_F_ROOT: u16 = libc::NLM_F_ROOT as u16;
/// Return all entries matching criteria passed in message content.
pub const NLM_F_MATCH: u16 = libc::NLM_F_MATCH as u16;
/// Return an atomic snapshot of the table. Requires `CAP_NET_ADMIN` capability or a effective UID
/// of 0.
pub const NLM_F_ATOMIC: u16 = libc::NLM_F_ATOMIC as u16;

// Additional flag bits for NEW requests
// =====================================

/// Replace existing matching object.
pub const NLM_F_REPLACE: u16 = libc::NLM_F_REPLACE as u16;
/// Don't replace if the object already exists.
pub const NLM_F_EXCL: u16 = libc::NLM_F_EXCL as u16;
/// Create object if it doesn't already exist.
pub const NLM_F_CREATE: u16 = libc::NLM_F_CREATE as u16;
/// Add to the end of the object list.
pub const NLM_F_APPEND: u16 = libc::NLM_F_APPEND as u16;

// Additional flag bits for DELETE requests
// =====================================

/// Do not delete recursively
pub const NLM_F_NONREC: u16 = constants::NLM_F_NONREC as u16;

// Additional flag bits for ACK requests
// =====================================

/// request was capped
pub const NLM_F_CAPPED: u16 = constants::NLM_F_CAPPED as u16;
/// extended ACK TVLs were included
pub const NLM_F_ACK_TLVS: u16 = constants::NLM_F_ACK_TLVS as u16;

/// Represent the flags field in a netlink packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Flags(u16);

impl From<u16> for Flags {
    fn from(flags: u16) -> Self {
        Flags(flags)
    }
}

impl<'a> Into<u16> for &'a Flags {
    fn into(self) -> u16 {
        self.0
    }
}

impl Into<u16> for Flags {
    fn into(self) -> u16 {
        self.0
    }
}

impl Default for Flags {
    fn default() -> Self {
        Flags::new()
    }
}

impl Flags {
    /// Create a new empty flags field (no flag is set)
    pub fn new() -> Self {
        Flags(0)
    }

    /// Set the `NLM_F_REQUEST` flag
    pub fn set_request(&mut self) {
        self.0 |= NLM_F_REQUEST;
    }

    /// Check if the `NLM_F_REQUEST` flag is set
    pub fn has_request(&self) -> bool {
        self.0 & NLM_F_REQUEST == NLM_F_REQUEST
    }

    /// Set the `NLM_MULTIPART` flag
    pub fn set_multipart(&mut self) {
        self.0 |= NLM_MULTIPART
    }
    /// Check if the `NLM_MULTIPART` flag is set
    pub fn has_multipart(&self) -> bool {
        self.0 & NLM_MULTIPART == NLM_MULTIPART
    }

    /// Set the `NLM_F_ACK` flag
    pub fn set_ack(&mut self) {
        self.0 |= NLM_F_ACK
    }
    /// Check if the `NLM_F_ACK` flag is set
    pub fn has_ack(&self) -> bool {
        self.0 & NLM_F_ACK == NLM_F_ACK
    }

    /// Set the `NLM_F_ECHO` flag
    pub fn set_echo(&mut self) {
        self.0 |= NLM_F_ECHO
    }
    /// Check if the `NLM_F_ECHO` flag is set
    pub fn has_echo(&self) -> bool {
        self.0 & NLM_F_ECHO == NLM_F_ECHO
    }

    /// Set the `NLM_F_DUMP_INTR` flag
    pub fn set_dump_intr(&mut self) {
        self.0 |= NLM_F_DUMP_INTR
    }
    /// Check if the `NLM_F_DUMP_INTR` flag is set
    pub fn has_dump_intr(&self) -> bool {
        self.0 & NLM_F_DUMP_INTR == NLM_F_DUMP_INTR
    }

    /// Set the `NLM_F_DUMP_FILTERED` flag
    pub fn set_dump_filterd(&mut self) {
        self.0 |= NLM_F_DUMP_FILTERED
    }
    /// Check if the `NLM_F_DUMP_FILTERED` flag is set
    pub fn has_dump_filterd(&self) -> bool {
        self.0 & NLM_F_DUMP_FILTERED == NLM_F_DUMP_FILTERED
    }

    /// Set the `NLM_F_ROOT` flag
    pub fn set_root(&mut self) {
        self.0 |= NLM_F_ROOT
    }
    /// Check if the `NLM_F_ROOT` flag is set
    pub fn has_root(&self) -> bool {
        self.0 & NLM_F_ROOT == NLM_F_ROOT
    }

    /// Set the `NLM_F_MATCH` flag
    pub fn set_match(&mut self) {
        self.0 |= NLM_F_MATCH
    }
    /// Check if the `NLM_F_MATCH` flag is set
    pub fn has_match(&self) -> bool {
        self.0 & NLM_F_MATCH == NLM_F_MATCH
    }

    /// Set the `NLM_F_ATOMIC` flag
    pub fn set_atomic(&mut self) {
        self.0 |= NLM_F_ATOMIC
    }
    /// Check if the `NLM_F_ATOMIC` flag is set
    pub fn has_atomic(&self) -> bool {
        self.0 & NLM_F_ATOMIC == NLM_F_ATOMIC
    }

    /// Set the `NLM_F_REPLACE` flag
    pub fn set_replace(&mut self) {
        self.0 |= NLM_F_REPLACE
    }
    /// Check if the `NLM_F_REPLACE` flag is set
    pub fn has_replace(&self) -> bool {
        self.0 & NLM_F_REPLACE == NLM_F_REPLACE
    }

    /// Set the `NLM_F_EXCL` flag
    pub fn set_excl(&mut self) {
        self.0 |= NLM_F_EXCL
    }
    /// Check if the `NLM_F_EXCL` flag is set
    pub fn has_excl(&self) -> bool {
        self.0 & NLM_F_EXCL == NLM_F_EXCL
    }

    /// Set the `NLM_F_CREATE` flag
    pub fn set_create(&mut self) {
        self.0 |= NLM_F_CREATE
    }
    /// Check if the `NLM_F_CREATE` flag is set
    pub fn has_create(&self) -> bool {
        self.0 & NLM_F_CREATE == NLM_F_CREATE
    }

    /// Set the `NLM_F_APPEND` flag
    pub fn set_append(&mut self) {
        self.0 |= NLM_F_APPEND
    }
    /// Check if the `NLM_F_APPEND` flag is set
    pub fn has_append(&self) -> bool {
        self.0 & NLM_F_APPEND == NLM_F_APPEND
    }

    /// Set the `NLM_F_NONREC` flag
    pub fn set_nonrec(&mut self) {
        self.0 |= NLM_F_NONREC
    }
    /// Check if the `NLM_F_NONREC` flag is set
    pub fn has_nonrec(&self) -> bool {
        self.0 & NLM_F_NONREC == NLM_F_NONREC
    }

    /// Set the `NLM_F_ACK_TLVS` flag
    pub fn set_ack_tvls(&mut self) {
        self.0 |= NLM_F_ACK_TLVS
    }
    /// Check if the `NLM_F_ACK_TLVS` flag is set
    pub fn has_ack_tvls(&mut self) -> bool {
        self.0 & NLM_F_ACK_TLVS == NLM_F_ACK_TLVS
    }

    /// Set the `NLM_F_CAPPED` flag
    pub fn set_capped(&mut self) {
        self.0 |= NLM_F_CAPPED
    }
    /// Check if the `NLM_F_CAPPED` flag is set
    pub fn has_capped(&self) -> bool {
        self.0 & NLM_F_CAPPED == NLM_F_CAPPED
    }
}
