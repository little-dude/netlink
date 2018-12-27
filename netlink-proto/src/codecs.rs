use failure::Fail;
use std::io;
use std::marker::PhantomData;

// FIXME: for some reason, the compiler says BufMut and Emitable are unused, but they _are_ used.
// These traits need to be in scope for some methods to be called.

use bytes::{BufMut, BytesMut};
use netlink_packet::{DecodeError, Emitable, NetlinkBuffer, NetlinkMessage};
use tokio_io::codec::{Decoder, Encoder};

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

impl Decoder for NetlinkCodec<NetlinkMessage> {
    type Item = NetlinkMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // This is a bit hacky because we don't want to keep `src` borrowed, since we need to
        // mutate it later.
        let len = match NetlinkBuffer::new_checked(src.as_ref()) {
            Ok(buf) => Some(buf.length() as usize),
            Err(DecodeError { .. }) => {
                if !src.as_ref().is_empty() {
                    // If this fails, that means we either received a truncated packet, or the
                    // packet if malformed (invalid length field). If the packet is truncated,
                    // there's not point in waiting for more bytes, because netlink is a datagram
                    // protocol so packets cannot be partially read from the netlink socket. Here
                    // is what the `recvfrom` man page says:
                    //
                    // > For message-based sockets, such as SOCK_RAW, SOCK_DGRAM, and
                    // > SOCK_SEQPACKET, the entire message shall be read in a single operation. If
                    // > a message is too long to fit in the supplied buffer, and MSG_PEEK is not
                    // > set in the flags argument, the excess bytes shall be discarded.
                    //
                    // At this point, there's no way to decode other packets, because we cannot
                    // know where they start, so we have empty the buffer and wait for new packets,
                    // potentially losing some valid messages.
                    error!("failed to find boundaries of a valid netlink packet");
                }
                None
            }
        };

        if let Some(len) = len {
            let bytes = src.split_to(len);
            match NetlinkMessage::from_bytes(&bytes) {
                Ok(packet) => Ok(Some(packet)),
                Err(mut e) => {
                    let mut error_string = format!("failed to decode packet {:x?}", &bytes);
                    for cause in e.causes() {
                        error_string += &format!(": {}", cause);
                    }
                    error!("{}", error_string);
                    // Try to decode the next packet, if any.
                    self.decode(src)
                }
            }
        } else {
            src.clear();
            Ok(None)
        }
    }
}

impl Encoder for NetlinkCodec<NetlinkMessage> {
    type Item = NetlinkMessage;
    type Error = io::Error;

    fn encode(&mut self, mut msg: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let msg_len = msg.buffer_len();
        // FIXME: we should have a max length for the buffer
        while buf.remaining_mut() < msg_len {
            let new_len = buf.len() + 2048;
            buf.resize(new_len, 0);
        }
        unsafe {
            let size = msg
                .to_bytes(&mut buf.bytes_mut()[..])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
            buf.advance_mut(size);
        }
        Ok(())
    }
}
