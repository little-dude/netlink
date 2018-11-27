use rtnetlink::NetlinkMessage;
use std::io;

#[derive(Fail, Debug)]
pub enum NetlinkIpError {
    #[fail(display = "The netlink connection is closed")]
    ConnectionClosed,

    #[fail(display = "{}", _0)]
    Io(#[cause] io::Error),

    #[fail(display = "Received an unexpected message")]
    UnexpectedMessage(NetlinkMessage),

    #[fail(display = "Did not receive an ACK for a request")]
    NoAck,

    #[fail(
        display = "Received an error message as a response: {:?}",
        _0
    )]
    NetlinkError(NetlinkMessage),

    #[fail(
        display = "Received a link message (RTM_GETLINK, RTM_NEWLINK, RTM_SETLINK or RTMGETLINK) with an invalid hardware address attribute."
    )]
    InvalidLinkAddress(Vec<u8>),

    #[fail(
        display = "Received an address message (RTM_GETADDR, RTM_NEWADDR or RTM_DELADDR) with an invalid address attribute."
    )]
    InvalidAddress(Vec<u8>),
}
