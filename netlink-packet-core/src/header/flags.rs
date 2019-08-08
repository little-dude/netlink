/// Must be set on all request messages (typically from user space to kernel space)
pub const NLM_F_REQUEST: u16 = 1;
///  Indicates the message is part of a multipart message terminated by NLMSG_DONE
pub const NLM_F_MULTIPART: u16 = 2;
/// Request for an acknowledgment on success. Typical direction of request is from user space
/// (CPC) to kernel space (FEC).
pub const NLM_F_ACK: u16 = 4;
/// Echo this request.  Typical direction of request is from user space (CPC) to kernel space
/// (FEC).
pub const NLM_F_ECHO: u16 = 8;
/// Dump was inconsistent due to sequence change
pub const NLM_F_DUMP_INTR: u16 = 16;
/// Dump was filtered as requested
pub const NLM_F_DUMP_FILTERED: u16 = 32;
/// Return the complete table instead of a single entry.
pub const NLM_F_ROOT: u16 = 256;
/// Return all entries matching criteria passed in message content.
pub const NLM_F_MATCH: u16 = 512;
/// Return an atomic snapshot of the table. Requires `CAP_NET_ADMIN` capability or a effective UID
/// of 0.
pub const NLM_F_ATOMIC: u16 = 1024;
pub const NLM_F_DUMP: u16 = 768;
/// Replace existing matching object.
pub const NLM_F_REPLACE: u16 = 256;
/// Don't replace if the object already exists.
pub const NLM_F_EXCL: u16 = 512;
/// Create object if it doesn't already exist.
pub const NLM_F_CREATE: u16 = 1024;
/// Add to the end of the object list.
pub const NLM_F_APPEND: u16 = 2048;

/// Do not delete recursively
pub const NLM_F_NONREC: u16 = 256;
/// request was capped
pub const NLM_F_CAPPED: u16 = 256;
/// extended ACK TVLs were included
pub const NLM_F_ACK_TLVS: u16 = 512;

/// Represent the flags field in a netlink packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct NetlinkFlags(u16);

impl From<u16> for NetlinkFlags {
    fn from(flags: u16) -> Self {
        NetlinkFlags(flags)
    }
}

impl<'a> From<&'a NetlinkFlags> for u16 {
    fn from(flags: &'a NetlinkFlags) -> u16 {
        flags.0
    }
}

impl From<NetlinkFlags> for u16 {
    fn from(flags: NetlinkFlags) -> u16 {
        flags.0
    }
}

impl Default for NetlinkFlags {
    fn default() -> Self {
        NetlinkFlags::new()
    }
}

impl NetlinkFlags {
    /// Create a new empty flags field (no flag is set)
    pub fn new() -> Self {
        NetlinkFlags(0)
    }

    /// Set the `NLM_F_REQUEST` flag
    pub fn set_request(&mut self) -> &mut Self {
        self.0 |= NLM_F_REQUEST;
        self
    }

    /// Check if the `NLM_F_REQUEST` flag is set
    pub fn has_request(self) -> bool {
        self.0 & NLM_F_REQUEST == NLM_F_REQUEST
    }

    /// Set the `NLM_F_MULTIPART` flag
    pub fn set_multipart(&mut self) -> &mut Self {
        self.0 |= NLM_F_MULTIPART;
        self
    }
    /// Check if the `NLM_F_MULTIPART` flag is set
    pub fn has_multipart(self) -> bool {
        self.0 & NLM_F_MULTIPART == NLM_F_MULTIPART
    }

    /// Set the `NLM_F_ACK` flag
    pub fn set_ack(&mut self) -> &mut Self {
        self.0 |= NLM_F_ACK;
        self
    }
    /// Check if the `NLM_F_ACK` flag is set
    pub fn has_ack(self) -> bool {
        self.0 & NLM_F_ACK == NLM_F_ACK
    }

    /// Set the `NLM_F_ECHO` flag
    pub fn set_echo(&mut self) -> &mut Self {
        self.0 |= NLM_F_ECHO;
        self
    }
    /// Check if the `NLM_F_ECHO` flag is set
    pub fn has_echo(self) -> bool {
        self.0 & NLM_F_ECHO == NLM_F_ECHO
    }

    /// Set the `NLM_F_DUMP_INTR` flag
    pub fn set_dump_intr(&mut self) -> &mut Self {
        self.0 |= NLM_F_DUMP_INTR;
        self
    }
    /// Check if the `NLM_F_DUMP_INTR` flag is set
    pub fn has_dump_intr(self) -> bool {
        self.0 & NLM_F_DUMP_INTR == NLM_F_DUMP_INTR
    }

    /// Set the `NLM_F_DUMP_FILTERED` flag
    pub fn set_dump_filterd(&mut self) -> &mut Self {
        self.0 |= NLM_F_DUMP_FILTERED;
        self
    }
    /// Check if the `NLM_F_DUMP_FILTERED` flag is set
    pub fn has_dump_filterd(self) -> bool {
        self.0 & NLM_F_DUMP_FILTERED == NLM_F_DUMP_FILTERED
    }

    /// Set the `NLM_F_ROOT` flag
    pub fn set_root(&mut self) -> &mut Self {
        self.0 |= NLM_F_ROOT;
        self
    }
    /// Check if the `NLM_F_ROOT` flag is set
    pub fn has_root(self) -> bool {
        self.0 & NLM_F_ROOT == NLM_F_ROOT
    }

    /// Set the `NLM_F_MATCH` flag
    pub fn set_match(&mut self) -> &mut Self {
        self.0 |= NLM_F_MATCH;
        self
    }
    /// Check if the `NLM_F_MATCH` flag is set
    pub fn has_match(self) -> bool {
        self.0 & NLM_F_MATCH == NLM_F_MATCH
    }

    /// Set the `NLM_F_ATOMIC` flag
    pub fn set_atomic(&mut self) -> &mut Self {
        self.0 |= NLM_F_ATOMIC;
        self
    }
    /// Check if the `NLM_F_ATOMIC` flag is set
    pub fn has_atomic(self) -> bool {
        self.0 & NLM_F_ATOMIC == NLM_F_ATOMIC
    }

    /// Set the `NLM_F_DUMP` flag
    pub fn set_dump(&mut self) -> &mut Self {
        self.0 |= NLM_F_DUMP;
        self
    }
    /// Check if the `NLM_F_DUMP` flag is set
    pub fn has_dump(self) -> bool {
        self.0 & NLM_F_DUMP == NLM_F_DUMP
    }

    /// Set the `NLM_F_REPLACE` flag
    pub fn set_replace(&mut self) -> &mut Self {
        self.0 |= NLM_F_REPLACE;
        self
    }
    /// Check if the `NLM_F_REPLACE` flag is set
    pub fn has_replace(self) -> bool {
        self.0 & NLM_F_REPLACE == NLM_F_REPLACE
    }

    /// Set the `NLM_F_EXCL` flag
    pub fn set_excl(&mut self) -> &mut Self {
        self.0 |= NLM_F_EXCL;
        self
    }
    /// Check if the `NLM_F_EXCL` flag is set
    pub fn has_excl(self) -> bool {
        self.0 & NLM_F_EXCL == NLM_F_EXCL
    }

    /// Set the `NLM_F_CREATE` flag
    pub fn set_create(&mut self) -> &mut Self {
        self.0 |= NLM_F_CREATE;
        self
    }
    /// Check if the `NLM_F_CREATE` flag is set
    pub fn has_create(self) -> bool {
        self.0 & NLM_F_CREATE == NLM_F_CREATE
    }

    /// Set the `NLM_F_APPEND` flag
    pub fn set_append(&mut self) -> &mut Self {
        self.0 |= NLM_F_APPEND;
        self
    }
    /// Check if the `NLM_F_APPEND` flag is set
    pub fn has_append(self) -> bool {
        self.0 & NLM_F_APPEND == NLM_F_APPEND
    }

    /// Set the `NLM_F_NONREC` flag
    pub fn set_nonrec(&mut self) -> &mut Self {
        self.0 |= NLM_F_NONREC;
        self
    }
    /// Check if the `NLM_F_NONREC` flag is set
    pub fn has_nonrec(self) -> bool {
        self.0 & NLM_F_NONREC == NLM_F_NONREC
    }

    /// Set the `NLM_F_ACK_TLVS` flag
    pub fn set_ack_tvls(&mut self) -> &mut Self {
        self.0 |= NLM_F_ACK_TLVS;
        self
    }
    /// Check if the `NLM_F_ACK_TLVS` flag is set
    pub fn has_ack_tvls(self) -> bool {
        self.0 & NLM_F_ACK_TLVS == NLM_F_ACK_TLVS
    }

    /// Set the `NLM_F_CAPPED` flag
    pub fn set_capped(&mut self) -> &mut Self {
        self.0 |= NLM_F_CAPPED;
        self
    }

    /// Check if the `NLM_F_CAPPED` flag is set
    pub fn has_capped(self) -> bool {
        self.0 & NLM_F_CAPPED == NLM_F_CAPPED
    }
}
