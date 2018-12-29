use failure::Fail;
use std::io;
use std::marker::PhantomData;

// FIXME: for some reason, the compiler says BufMut and Emitable are unused, but they _are_ used.
// These traits need to be in scope for some methods to be called.

use bytes::{BufMut, BytesMut};
use netlink_packet::{Emitable, NetlinkBuffer, NetlinkMessage};
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

// FIXME: it seems that for audit, we're receiving malformed packets.
// See https://github.com/mozilla/libaudit-go/issues/24
impl Decoder for NetlinkCodec<NetlinkMessage> {
    type Item = NetlinkMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        debug!("NetlinkCodec: decoding next message");
        // If there's nothing to read, return Ok(None)
        if src.as_ref().is_empty() {
            trace!("buffer is empty");
            src.clear();
            return Ok(None);
        }

        // This is a bit hacky because we don't want to keep `src` borrowed, since we need to
        // mutate it later.
        let len = match NetlinkBuffer::new_checked(src.as_ref()) {
            #[cfg(not(feature = "audit"))]
            Ok(buf) => buf.length() as usize,
            #[cfg(feature = "audit")]
            Ok(buf) => {
                if src.as_ref().len() as isize - buf.length() as isize == 16 {
                    // The audit messages are sometimes truncated, because the length specified in
                    // the header, does not take the header itself into account. To workaround
                    // this, we tweak the length.
                    // See also: https://github.com/mozilla/libaudit-go/issues/24
                    warn!("found what looks like a truncated audit packet");
                    src.as_ref().len()
                } else {
                    buf.length() as usize
                }
            }
            Err(e) => {
                // We either received a truncated packet, or the packet if malformed (invalid
                // length field). If the packet is truncated, there's not point in waiting for
                // more bytes, because netlink is a datagram protocol so packets cannot be
                // partially read from the netlink socket. Here is what the `recvfrom` man page
                // says:
                //
                // > For message-based sockets, such as SOCK_RAW, SOCK_DGRAM, and >
                // SOCK_SEQPACKET, the entire message shall be read in a single operation. If >
                // a message is too long to fit in the supplied buffer, and MSG_PEEK is not >
                // set in the flags argument, the excess bytes shall be discarded.
                //
                // At this point, there's no way to decode other packets, because we cannot
                // know where they start, so we just error out.
                error!("{:?}: {:#x?}.", e, src.as_ref());
                return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)));
            }
        };

        #[cfg(feature = "audit")]
        let bytes = {
            let mut bytes = src.split_to(len);
            {
                let mut buf = NetlinkBuffer::new(bytes.as_mut());
                // If the buffer contains more bytes than what the header says the length is, it
                // means we ran into a malformed packet (see comment above), and we just set the
                // "right" length ourself, so that parsing does not fail.
                //
                // How do we know that's the right length? Due to an implementation detail and to
                // the fact that netlink is a datagram protocol.
                //
                // - our implementation of Stream always calls the codec with at most 1 message in
                //   the buffer, so we know the extra bytes do not belong to another message.
                // - because netlink is a datagram protocol, we receive entire messages, so we know
                //   that if those extra bytes do not belong to another message, they belong to
                //   this one.
                if len != buf.length() as usize {
                    warn!(
                        "setting packet length to {} instead of {}",
                        len,
                        buf.length()
                    );
                    buf.set_length(len as u32);
                }
            }
            bytes
        };

        #[cfg(not(feature = "audit"))]
        let bytes = src.split_to(len);

        match NetlinkMessage::from_bytes(&bytes) {
            Ok(packet) => Ok(Some(packet)),
            Err(e) => {
                let mut error_string = format!("failed to decode packet {:#x?}", &bytes);
                for cause in e.causes() {
                    error_string += &format!(": {}", cause);
                }
                error!("{}", error_string);
                Ok(None)
            }
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
