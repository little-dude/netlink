use netlink_sys::rtnl::Message;
use std::io;

#[derive(Fail, Debug)]
pub enum NetlinkIpError {
    #[fail(display = "The netlink connection is closed")]
    ConnectionClosed,

    #[fail(display = "{}", _0)]
    Io(#[cause] io::Error),

    #[fail(display = "Received an unexpected message")]
    UnexpectedMessage(Message),

    #[fail(
        display = "Received a link message (RTM_GETLINK, RTM_NEWLINK, RTM_SETLINK or RTMGETLINK) with an invalid hardware address attribute."
    )]
    InvalidLinkAddress(Vec<u8>),
}
