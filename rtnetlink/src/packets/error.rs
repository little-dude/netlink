use byteorder::{ByteOrder, NativeEndian};
use std::mem::size_of;
use {
    Emitable, Error, Field, NetlinkBuffer, NetlinkHeader, Parseable, Rest, Result,
    NETLINK_HEADER_LEN,
};

const CODE: Field = 0..4;
const PAYLOAD: Rest = 4..;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ErrorBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ErrorBuffer<T> {
    pub fn new(buffer: T) -> ErrorBuffer<T> {
        ErrorBuffer { buffer }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the error code
    pub fn code(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[CODE])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ErrorBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[PAYLOAD]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> ErrorBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ErrorBuffer<T> {
    /// set the error code field
    pub fn set_code(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_i32(&mut data[CODE], value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    pub code: i32,
    pub header: NetlinkHeader,
}

pub type AckMessage = ErrorMessage;

impl Emitable for ErrorMessage {
    fn buffer_len(&self) -> usize {
        size_of::<i32>() + self.header.buffer_len()
    }
    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = ErrorBuffer::new(buffer);
        buffer.set_code(self.code);
        self.header.emit(buffer.payload_mut())
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<ErrorMessage> for ErrorBuffer<&'buffer T> {
    fn parse(&self) -> Result<ErrorMessage> {
        let header: NetlinkHeader = {
            if self.payload().len() < NETLINK_HEADER_LEN {
                return Err(Error::Truncated);
            }
            NetlinkBuffer::new(self.payload()).parse()?
        };
        Ok(ErrorMessage {
            code: self.code(),
            header,
        })
    }
}
