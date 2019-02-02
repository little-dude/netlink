use std::mem;

use byteorder::{ByteOrder, NativeEndian};

use crate::Field;

pub const SDIAG_FAMILY: usize = 0;
pub const SDIAG_PROTOCOL: usize = 1;

pub const fn array_of<T>(start: usize, len: usize) -> Field {
    start..(start + mem::size_of::<T>() * len)
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
const RTA_HDR_LEN: usize = mem::size_of::<u16>() * 2;

const RTA_LENGTH: Field = 0..2;
const RTA_TYPE: Field = 2..4;

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

        let len = NativeEndian::read_u16(&data[RTA_LENGTH]) as usize;
        let ty = NativeEndian::read_u16(&data[RTA_TYPE]);

        if len < RTA_HDR_LEN || len >= data.len() {
            return None;
        }

        let payload = &data[RTA_HDR_LEN..len];

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
