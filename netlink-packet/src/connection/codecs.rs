use std::marker::PhantomData;

// FIXME: for some reason, the compiler says BufMut and Emitable are unused, but they _are_ used.
// These traits need to be in scope for some methods to be called.

use bytes::{BufMut, BytesMut};
use packets::NetlinkMessage;
use tokio_io::codec::{Decoder, Encoder};

use {Emitable, NetlinkPacketError, NetlinkBuffer};

pub struct NetlinkCodec<T> {
    phantom: PhantomData<T>,
}

impl<T> Default for NetlinkCodec<T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T> NetlinkCodec<T> {
    pub fn new() -> Self {
        NetlinkCodec {
            phantom: PhantomData,
        }
    }
}

impl<T> Decoder for NetlinkCodec<NetlinkBuffer<T>>
where
    T: for<'a> From<&'a [u8]> + AsRef<[u8]>,
{
    type Item = NetlinkBuffer<T>;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let len = match NetlinkBuffer::new_checked(src.as_ref()) {
            Ok(buf) => buf.length() as usize,
            Err(NetlinkPacketError::Decode) => return Ok(None),
            // This should not happen. Errors should only occur if the message is not as long as
            // the length field in the header says it is.
            Err(e) => panic!("Unknown error while reading packet: {}", e),
        };
        let bytes = src.split_to(len);
        Ok(Some(NetlinkBuffer::new(T::from(&bytes))))
    }
}

impl<T: AsRef<[u8]>> Encoder for NetlinkCodec<NetlinkBuffer<T>> {
    type Item = NetlinkBuffer<T>;
    type Error = Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.extend_from_slice(msg.into_inner().as_ref());
        Ok(())
    }
}

impl Decoder for NetlinkCodec<NetlinkMessage> {
    type Item = NetlinkMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let len = match NetlinkBuffer::new_checked(src.as_ref()) {
            Ok(buf) => buf.length() as usize,
            Err(NetlinkPacketError::Decode) => {
                return Ok(None);
            }
            Err(e) => panic!("Unknown error while reading packet: {}", e),
        };
        let bytes = src.split_to(len);
        Ok(Some(NetlinkMessage::from_bytes(&bytes).unwrap()))
    }
}
impl Encoder for NetlinkCodec<NetlinkMessage> {
    type Item = NetlinkMessage;
    type Error = Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let msg_len = msg.buffer_len();
        // FIXME: we should have a max length for the buffer
        while buf.remaining_mut() < msg_len {
            let new_len = buf.len() + 2048;
            buf.resize(new_len, 0);
        }
        unsafe {
            let size = msg.to_bytes(&mut buf.bytes_mut()[..])?;
            buf.advance_mut(size);
        }
        Ok(())
    }
}
