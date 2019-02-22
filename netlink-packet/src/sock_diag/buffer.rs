use std::mem;
use std::ptr::NonNull;

use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Field, Parseable, Rest};

pub const REQ_FAMILY: usize = 0;
pub const REQ_PROTOCOL: usize = 1;

pub const fn array_of<T>(start: usize, len: usize) -> Field {
    start..(start + mem::size_of::<T>() * len)
}

pub trait CStruct: Sized {}

impl<T: AsRef<[u8]>, S: CStruct> Parseable<S> for T {
    fn parse(&self) -> Result<S, DecodeError> {
        let data = self.as_ref();

        if data.len() >= mem::size_of::<S>() {
            Ok(unsafe {
                NonNull::new_unchecked(data.as_ptr() as *mut u8)
                    .cast::<S>()
                    .as_ptr()
                    .read()
            })
        } else {
            Err(format!(
                "buffer size is {}, whereas a buffer is at least {} long",
                data.len(),
                mem::size_of::<S>()
            )
            .into())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtaIterator<T> {
    position: usize,
    buffer: T,
}

impl<T> RtaIterator<T> {
    pub fn new(buffer: T) -> Self {
        RtaIterator {
            position: 0,
            buffer,
        }
    }
}

const RTA_ALIGNTO: usize = 4;
pub const RTA_HDR_LEN: usize = mem::size_of::<u16>() * 2;

const RTA_LENGTH: Field = 0..2;
const RTA_TYPE: Field = 2..4;
const RTA_PAYLOAD: Rest = 4..;

impl<'buffer, T: AsRef<[u8]> + ?Sized + 'buffer> Iterator for RtaIterator<&'buffer T> {
    type Item = (u16, &'buffer [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        // rtattr are aligned on 4 bytes boundaries, so we make sure we ignore any potential padding.
        let offset = self.position % RTA_ALIGNTO;
        if offset != 0 {
            self.position += RTA_ALIGNTO - offset;
        }

        let data = self.buffer.as_ref();

        if self.position >= data.len() {
            return None;
        }

        let data = &data[self.position..];

        if data.len() < RTA_HDR_LEN {
            return None;
        }

        let buf = RtaBuffer::new(data);
        let len = buf.len() as usize;
        let ty = buf.ty();
        let payload = &data[buf.payload_field()?];

        trace!(
            "parse {:?} extension at {} with {} bytes: {:?}",
            ty,
            self.position,
            payload.len(),
            payload
        );

        self.position += len;

        Some((ty, payload))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RtaBuffer<T> {
    buffer: T,
}

impl<T> RtaBuffer<T> {
    pub fn new(buffer: T) -> RtaBuffer<T> {
        RtaBuffer { buffer }
    }
}

impl<T: AsRef<[u8]>> RtaBuffer<T> {
    pub fn len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[RTA_LENGTH])
    }

    pub fn ty(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[RTA_TYPE])
    }

    pub fn payload_field(&self) -> Option<Field> {
        let data = self.buffer.as_ref();
        let len = self.len() as usize;

        if len < RTA_HDR_LEN || len >= data.len() {
            None
        } else {
            Some(RTA_PAYLOAD.start..len)
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RtaBuffer<T> {
    pub fn set_len(&mut self, len: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[RTA_LENGTH], len);
    }

    pub fn set_ty(&mut self, ty: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[RTA_TYPE], ty);
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[RTA_PAYLOAD]
    }
}

bitflags! {
    /// The shutdown state
    pub struct Shutdown: u8 {
        const NONE = 0;
        const RECV = RCV_SHUTDOWN;
        const SEND = SEND_SHUTDOWN;
    }
}

const RCV_SHUTDOWN: u8 = 1;
const SEND_SHUTDOWN: u8 = 2;
