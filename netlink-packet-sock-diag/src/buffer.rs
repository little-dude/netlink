use crate::{
    constants::*,
    inet,
    traits::{Parseable, ParseableParametrized},
    unix,
    DecodeError,
    SockDiagMessage,
};
use anyhow::Context;

const BUF_MIN_LEN: usize = 2;

pub struct SockDiagBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> SockDiagBuffer<T> {
    pub fn new(buffer: T) -> SockDiagBuffer<T> {
        SockDiagBuffer { buffer }
    }

    pub fn length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub(crate) fn check_len(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < BUF_MIN_LEN {
            return Err(format!(
                "invalid buffer: length is {} but packets are at least {} bytes",
                len, BUF_MIN_LEN
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn family(&self) -> u8 {
        self.buffer.as_ref()[0]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> SockDiagBuffer<&'a T> {
    pub fn inner(&self) -> &'a [u8] {
        &self.buffer.as_ref()[..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> SockDiagBuffer<&'a mut T> {
    pub fn inner_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..]
    }
}

impl<'a, T: AsRef<[u8]>> ParseableParametrized<SockDiagBuffer<&'a T>, u16> for SockDiagMessage {
    fn parse_with_param(
        buf: &SockDiagBuffer<&'a T>,
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        use self::SockDiagMessage::*;
        buf.check_len()?;
        let message = match (message_type, buf.family()) {
            (SOCK_DIAG_BY_FAMILY, AF_INET) => {
                let err = "invalid AF_INET response";
                let buf = inet::InetResponseBuffer::new_checked(buf.inner()).context(err)?;
                InetResponse(Box::new(inet::InetResponse::parse(&buf).context(err)?))
            }
            (SOCK_DIAG_BY_FAMILY, AF_INET6) => {
                let err = "invalid AF_INET6 response";
                let buf = inet::InetResponseBuffer::new_checked(buf.inner()).context(err)?;
                InetResponse(Box::new(inet::InetResponse::parse(&buf).context(err)?))
            }
            (SOCK_DIAG_BY_FAMILY, AF_UNIX) => {
                let err = "invalid AF_UNIX response";
                let buf = unix::UnixResponseBuffer::new_checked(buf.inner()).context(err)?;
                UnixResponse(Box::new(unix::UnixResponse::parse(&buf).context(err)?))
            }
            (SOCK_DIAG_BY_FAMILY, af) => {
                return Err(format!("unknown address family {}", af).into())
            }
            _ => return Err(format!("unknown message type {}", message_type).into()),
        };
        Ok(message)
    }
}
