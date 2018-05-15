use constants;

// Generic message types

/// The message is ignored.
pub const NLMSG_NOOP: u16 = constants::NLMSG_NOOP as u16;
/// The message signals an error and the payload contains a nlmsgerr structure. This can be looked
/// at as a NACK and typically it is from FEC to CPC.
pub const NLMSG_ERROR: u16 = constants::NLMSG_ERROR as u16;
/// The message terminates a multipart message.
pub const NLMSG_DONE: u16 = constants::NLMSG_DONE as u16;
/// Data lost
pub const NLMSG_OVERRUN: u16 = constants::NLMSG_OVERRUN as u16;

// rtnetlink message types

pub const RTM_NEWLINK: u16 = constants::RTM_NEWLINK as u16;
pub const RTM_DELLINK: u16 = constants::RTM_DELLINK as u16;
pub const RTM_GETLINK: u16 = constants::RTM_GETLINK as u16;

/// Represent the message type field in a netlink packet header
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum MessageType {
    /// The message type is `NLMSG_NOOP`: the message is ignored.
    Noop,
    /// The message type is `NLMSG_ERROR`. The message signals an error and the payload contains a
    /// nlmsgerr structure. This can be looked at as a NACK and typically it is from FEC to CPC.
    Error,
    /// The message type is `NLMSG_DONE`: the message terminates a multipart message.
    Done,
    /// The message type is `NLMSG_OVERRUN`: data lost
    Overrun,
    /// The message type is `RTM_NEWLINK`
    NewLink,
    /// The message type is `RTM_DELLINK`
    DelLink,
    /// The message type is `RTM_GETLINK`
    GetLink,

    Other(u16),
}

impl From<u16> for MessageType {
    fn from(value: u16) -> Self {
        use self::MessageType::*;
        match value {
            NLMSG_NOOP => Noop,
            NLMSG_ERROR => Error,
            NLMSG_DONE => Done,
            NLMSG_OVERRUN => Overrun,
            RTM_NEWLINK => NewLink,
            RTM_DELLINK => DelLink,
            RTM_GETLINK => GetLink,
            _ => Other(value),
        }
    }
}

impl Into<u16> for MessageType {
    fn into(self) -> u16 {
        use self::MessageType::*;
        match self {
            Noop => NLMSG_NOOP,
            Error => NLMSG_ERROR,
            Done => NLMSG_DONE,
            Overrun => NLMSG_OVERRUN,
            NewLink => RTM_NEWLINK,
            DelLink => RTM_DELLINK,
            GetLink => RTM_GETLINK,
            Other(v) => v,
        }
    }
}
