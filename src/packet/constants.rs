pub mod message_type {
    use constants;
    /// The message is ignored.
    pub const NLMSG_NOOP: u16 = constants::NLMSG_NOOP as u16;
    /// The message signals an error and the payload contains a nlmsgerr structure. This can be looked
    /// at as a NACK and typically it is from FEC to CPC.
    pub const NLMSG_ERROR: u16 = constants::NLMSG_ERROR as u16;
    /// The message terminates a multipart message.
    pub const NLMSG_DONE: u16 = constants::NLMSG_DONE as u16;
    /// Data lost
    pub const NLMSG_OVERRUN: u16 = constants::NLMSG_OVERRUN as u16;

    pub const RTM_NEWLINK: u16 = constants::RTM_NEWLINK as u16;
    pub const RTM_DELLINK: u16 = constants::RTM_DELLINK as u16;
    pub const RTM_GETLINK: u16 = constants::RTM_GETLINK as u16;
    pub const RTM_SETLINK: u16 = constants::RTM_SETLINK as u16;
    pub const RTM_NEWADDR: u16 = constants::RTM_NEWADDR as u16;
    pub const RTM_DELADDR: u16 = constants::RTM_DELADDR as u16;
    pub const RTM_GETADDR: u16 = constants::RTM_GETADDR as u16;
    pub const RTM_NEWROUTE: u16 = constants::RTM_NEWROUTE as u16;
    pub const RTM_DELROUTE: u16 = constants::RTM_DELROUTE as u16;
    pub const RTM_GETROUTE: u16 = constants::RTM_GETROUTE as u16;
    pub const RTM_NEWNEIGH: u16 = constants::RTM_NEWNEIGH as u16;
    pub const RTM_DELNEIGH: u16 = constants::RTM_DELNEIGH as u16;
    pub const RTM_GETNEIGH: u16 = constants::RTM_GETNEIGH as u16;
    pub const RTM_NEWRULE: u16 = constants::RTM_NEWRULE as u16;
    pub const RTM_DELRULE: u16 = constants::RTM_DELRULE as u16;
    pub const RTM_GETRULE: u16 = constants::RTM_GETRULE as u16;
    pub const RTM_NEWQDISC: u16 = constants::RTM_NEWQDISC as u16;
    pub const RTM_DELQDISC: u16 = constants::RTM_DELQDISC as u16;
    pub const RTM_GETQDISC: u16 = constants::RTM_GETQDISC as u16;
    pub const RTM_NEWTCLASS: u16 = constants::RTM_NEWTCLASS as u16;
    pub const RTM_DELTCLASS: u16 = constants::RTM_DELTCLASS as u16;
    pub const RTM_GETTCLASS: u16 = constants::RTM_GETTCLASS as u16;
    pub const RTM_NEWTFILTER: u16 = constants::RTM_NEWTFILTER as u16;
    pub const RTM_DELTFILTER: u16 = constants::RTM_DELTFILTER as u16;
    pub const RTM_GETTFILTER: u16 = constants::RTM_GETTFILTER as u16;
    pub const RTM_NEWACTION: u16 = constants::RTM_NEWACTION as u16;
    pub const RTM_DELACTION: u16 = constants::RTM_DELACTION as u16;
    pub const RTM_GETACTION: u16 = constants::RTM_GETACTION as u16;
    pub const RTM_NEWPREFIX: u16 = constants::RTM_NEWPREFIX as u16;
    pub const RTM_GETMULTICAST: u16 = constants::RTM_GETMULTICAST as u16;
    pub const RTM_GETANYCAST: u16 = constants::RTM_GETANYCAST as u16;
    pub const RTM_NEWNEIGHTBL: u16 = constants::RTM_NEWNEIGHTBL as u16;
    pub const RTM_GETNEIGHTBL: u16 = constants::RTM_GETNEIGHTBL as u16;
    pub const RTM_SETNEIGHTBL: u16 = constants::RTM_SETNEIGHTBL as u16;
    pub const RTM_NEWNDUSEROPT: u16 = constants::RTM_NEWNDUSEROPT as u16;
    pub const RTM_NEWADDRLABEL: u16 = constants::RTM_NEWADDRLABEL as u16;
    pub const RTM_DELADDRLABEL: u16 = constants::RTM_DELADDRLABEL as u16;
    pub const RTM_GETADDRLABEL: u16 = constants::RTM_GETADDRLABEL as u16;
    pub const RTM_GETDCB: u16 = constants::RTM_GETDCB as u16;
    pub const RTM_SETDCB: u16 = constants::RTM_SETDCB as u16;
    pub const RTM_NEWNETCONF: u16 = constants::RTM_NEWNETCONF as u16;
    pub const RTM_DELNETCONF: u16 = constants::RTM_DELNETCONF as u16;
    pub const RTM_GETNETCONF: u16 = constants::RTM_GETNETCONF as u16;
    pub const RTM_NEWMDB: u16 = constants::RTM_NEWMDB as u16;
    pub const RTM_DELMDB: u16 = constants::RTM_DELMDB as u16;
    pub const RTM_GETMDB: u16 = constants::RTM_GETMDB as u16;
    pub const RTM_NEWNSID: u16 = constants::RTM_NEWNSID as u16;
    pub const RTM_DELNSID: u16 = constants::RTM_DELNSID as u16;
    pub const RTM_GETNSID: u16 = constants::RTM_GETNSID as u16;
    pub const RTM_NEWSTATS: u16 = constants::RTM_NEWSTATS as u16;
    pub const RTM_GETSTATS: u16 = constants::RTM_GETSTATS as u16;
    pub const RTM_NEWCACHEREPORT: u16 = constants::RTM_NEWCACHEREPORT as u16;
}

// Standard flag bits
// =====================================

pub mod flags {
    use constants;
    use libc;

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

    pub const NLM_F_DUMP: u16 = libc::NLM_F_DUMP as u16;

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
}
