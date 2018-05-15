use constants;

// Generic message types
const NOOP: u16 = constants::NLMSG_NOOP as u16;
const ERROR: u16 = constants::NLMSG_ERROR as u16;
const DONE: u16 = constants::NLMSG_DONE as u16;
const OVERRUN: u16 = constants::NLMSG_OVERRUN as u16;

// rtnetlink message types

const NEW_LINK: u16 = constants::RTM_NEWLINK as u16;
const DEL_LINK: u16 = constants::RTM_DELLINK as u16;
const GET_LINK: u16 = constants::RTM_GETLINK as u16;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum MessageType {
    /// Message is ignored.
    Noop,
    /// The message signals an error and the payload contains a nlmsgerr structure. This can be
    /// looked at as a NACK and typically it is from FEC to CPC.
    Error,
    /// Message terminates a multipart message.
    Done,
    /// Data lost
    Overrun,

    NewLink,
    DelLink,
    GetLink,

    Other(u16),
}

impl From<u16> for MessageType {
    fn from(value: u16) -> Self {
        use self::MessageType::*;
        match value {
            NOOP => Noop,
            ERROR => Error,
            DONE => Done,
            OVERRUN => Overrun,
            NEW_LINK => NewLink,
            DEL_LINK => DelLink,
            GET_LINK => GetLink,
            _ => Other(value),
        }
    }
}

impl Into<u16> for MessageType {
    fn into(self) -> u16 {
        use self::MessageType::*;
        match self {
            Noop => NOOP,
            Error => ERROR,
            Done => DONE,
            Overrun => OVERRUN,
            NewLink => NEW_LINK,
            DelLink => DEL_LINK,
            GetLink => GET_LINK,
            Other(v) => v,
        }
    }
}
