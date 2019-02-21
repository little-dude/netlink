use failure::ResultExt;

use netlink_sys::constants::{AF_INET, AF_INET6, AF_PACKET, AF_UNIX};

use crate::sock_diag::{inet, packet, sock::SOCK_DIAG_BY_FAMILY, unix};
use crate::{DecodeError, Emitable, Parseable};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Message {
    InetDiag(inet::Request),
    InetSock(inet::Response),
    UnixDiag(unix::Request),
    UnixSock(unix::Response),
    PacketDiag(packet::Request),
    PacketSock(packet::Response),
}

impl Emitable for Message {
    fn buffer_len(&self) -> usize {
        use Message::*;

        match self {
            InetDiag(ref req) => req.buffer_len(),
            UnixDiag(ref req) => req.buffer_len(),
            PacketDiag(ref req) => req.buffer_len(),
            _ => unimplemented!(),
        }
    }

    fn emit(&self, buf: &mut [u8]) {
        use Message::*;

        match self {
            InetDiag(ref req) => req.emit(buf),
            UnixDiag(ref req) => req.emit(buf),
            PacketDiag(ref req) => req.emit(buf),
            _ => unimplemented!(),
        }
    }
}

impl Message {
    pub(crate) fn parse(message_type: u16, buffer: &[u8]) -> Result<Self, DecodeError> {
        match message_type {
            SOCK_DIAG_BY_FAMILY if !buffer.is_empty() => match u16::from(buffer[0]) {
                AF_INET | AF_INET6 => Ok(Message::InetSock(
                    inet::ResponseBuffer::new_checked(buffer)
                        .context("failed to parse SOCK_DIAG_BY_FAMILY message")?
                        .parse()
                        .context("failed to parse SOCK_DIAG_BY_FAMILY message")?,
                )),
                AF_UNIX => Ok(Message::UnixSock(
                    unix::ResponseBuffer::new_checked(buffer)
                        .context("failed to parse SOCK_DIAG_BY_FAMILY message")?
                        .parse()
                        .context("failed to parse SOCK_DIAG_BY_FAMILY message")?,
                )),
                AF_PACKET => Ok(Message::PacketSock(
                    packet::ResponseBuffer::new_checked(buffer)
                        .context("failed to parse SOCK_DIAG_BY_FAMILY message")?
                        .parse()
                        .context("failed to parse SOCK_DIAG_BY_FAMILY message")?,
                )),
                family => Err(format!("Unknown message family: {}", family).into()),
            },
            _ => Err(format!("Unknown message type: {}", message_type).into()),
        }
    }

    pub fn message_type(&self) -> u16 {
        SOCK_DIAG_BY_FAMILY
    }
}
