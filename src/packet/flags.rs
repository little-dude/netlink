use constants;
use libc;

// Standard flag bits
// =====================================

/// Must be set on all request messages (typically from user space to kernel space)
pub const REQUEST: u16 = libc::NLM_F_REQUEST as u16;
///  Indicates the message is part of a multipart message terminated by NLMSG_DONE
pub const MULTIPART: u16 = libc::NLM_F_MULTI as u16;
/// Request for an acknowledgment on success. Typical direction of request is from user space
/// (CPC) to kernel space (FEC).
pub const ACK: u16 = libc::NLM_F_ACK as u16;
/// Echo this request.  Typical direction of request is from user space (CPC) to kernel space
/// (FEC).
pub const ECHO: u16 = libc::NLM_F_ECHO as u16;
/// Dump was inconsistent due to sequence change
pub const DUMP_INTR: u16 = libc::NLM_F_DUMP_INTR as u16;
/// Dump was filtered as requested
pub const DUMP_FILTERED: u16 = libc::NLM_F_DUMP_FILTERED as u16;

// Additional flag bits for GET requests
// =====================================

/// Return the complete table instead of a single entry.
pub const ROOT: u16 = libc::NLM_F_ROOT as u16;
/// Return all entries matching criteria passed in message content.
pub const MATCH: u16 = libc::NLM_F_MATCH as u16;
/// Return an atomic snapshot of the table. Requires `CAP_NET_ADMIN` capability or a effective UID
/// of 0.
pub const ATOMIC: u16 = libc::NLM_F_ATOMIC as u16;

// Additional flag bits for NEW requests
// =====================================

/// Replace existing matching object.
pub const REPLACE: u16 = libc::NLM_F_REPLACE as u16;
/// Don't replace if the object already exists.
pub const EXCL: u16 = libc::NLM_F_EXCL as u16;
/// Create object if it doesn't already exist.
pub const CREATE: u16 = libc::NLM_F_CREATE as u16;
/// Add to the end of the object list.
pub const APPEND: u16 = libc::NLM_F_APPEND as u16;

// Additional flag bits for DELETE requests
// =====================================

/// Do not delete recursively
pub const NONREC: u16 = constants::NLM_F_NONREC as u16;

// Additional flag bits for ACK requests
// =====================================

/// request was capped
pub const CAPPED: u16 = constants::NLM_F_CAPPED as u16;
/// extended ACK TVLs were included
pub const ACK_TLVS: u16 = constants::NLM_F_ACK_TLVS as u16;

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

impl Flags {
    pub fn new() -> Self {
        Flags(0)
    }

    pub fn set_request(&mut self) {
        self.0 |= REQUEST;
    }
    pub fn has_request(&self) -> bool {
        self.0 & REQUEST == REQUEST
    }

    pub fn set_multipart(&mut self) {
        self.0 |= MULTIPART
    }
    pub fn has_multipart(&self) -> bool {
        self.0 & MULTIPART == MULTIPART
    }

    pub fn set_ack(&mut self) {
        self.0 |= ACK
    }
    pub fn has_ack(&self) -> bool {
        self.0 & ACK == ACK
    }

    pub fn set_echo(&mut self) {
        self.0 |= ECHO
    }
    pub fn has_echo(&self) -> bool {
        self.0 & ECHO == ECHO
    }

    pub fn set_dump_intr(&mut self) {
        self.0 |= DUMP_INTR
    }
    pub fn has_dump_intr(&self) -> bool {
        self.0 & DUMP_INTR == DUMP_INTR
    }

    pub fn set_dump_filterd(&mut self) {
        self.0 |= DUMP_FILTERED
    }
    pub fn has_dump_filterd(&self) -> bool {
        self.0 & DUMP_FILTERED == DUMP_FILTERED
    }

    pub fn set_root(&mut self) {
        self.0 |= ROOT
    }
    pub fn has_root(&self) -> bool {
        self.0 & ROOT == ROOT
    }

    pub fn set_match(&mut self) {
        self.0 |= MATCH
    }
    pub fn has_match(&self) -> bool {
        self.0 & MATCH == MATCH
    }

    pub fn set_atomic(&mut self) {
        self.0 |= ATOMIC
    }
    pub fn has_atomic(&self) -> bool {
        self.0 & ATOMIC == ATOMIC
    }

    pub fn set_replace(&mut self) {
        self.0 |= REPLACE
    }
    pub fn has_replace(&self) -> bool {
        self.0 & REPLACE == REPLACE
    }

    pub fn set_excl(&mut self) {
        self.0 |= EXCL
    }
    pub fn has_excl(&self) -> bool {
        self.0 & EXCL == EXCL
    }

    pub fn set_create(&mut self) {
        self.0 |= CREATE
    }
    pub fn has_create(&self) -> bool {
        self.0 & CREATE == CREATE
    }

    pub fn set_append(&mut self) {
        self.0 |= APPEND
    }
    pub fn has_append(&self) -> bool {
        self.0 & APPEND == APPEND
    }

    pub fn set_nonrec(&mut self) {
        self.0 |= NONREC
    }
    pub fn has_nonrec(&self) -> bool {
        self.0 & NONREC == NONREC
    }

    pub fn set_ack_tvls(&mut self) {
        self.0 |= ACK_TLVS;
    }
    pub fn has_ack_tvls(&mut self) -> bool {
        self.0 & ACK_TLVS == ACK_TLVS
    }

    pub fn set_capped(&mut self) {
        self.0 |= CAPPED;
    }
    pub fn has_capped(&self) -> bool {
        self.0 & CAPPED == CAPPED
    }
}
