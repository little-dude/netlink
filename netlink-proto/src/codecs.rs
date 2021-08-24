use std::{fmt::Debug, io, marker::PhantomData};

use bytes::{BufMut, BytesMut};
use netlink_packet_core::{
    NetlinkBuffer, NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NetlinkSerializable,
};

use crate::sys::protocols::{NETLINK_AUDIT, NETLINK_GENERIC, NETLINK_KOBJECT_UEVENT};

use tokio_util::codec::{Decoder, Encoder};

#[derive(Eq, PartialEq)]
enum CodecType {
    /// Normal Netlink packet with header
    Packet,
    /// Audit packets lenght is unreliable
    AuditPacket,
    /// kobject_uevent packets do not have headers at all
    UEventPacket,
}

pub struct NetlinkCodec<T> {
    phantom: PhantomData<T>,
    ty: CodecType,
}

impl<T> Default for NetlinkCodec<T> {
    fn default() -> Self {
        Self::new(NETLINK_GENERIC)
    }
}

impl<T> NetlinkCodec<T> {
    pub fn new(protocol: isize) -> Self {
        let ty = match protocol {
            NETLINK_AUDIT => CodecType::AuditPacket,
            NETLINK_KOBJECT_UEVENT => CodecType::UEventPacket,
            _ => CodecType::Packet,
        };
        NetlinkCodec {
            phantom: PhantomData,
            ty,
        }
    }
}

// FIXME: it seems that for audit, we're receiving malformed packets.
// See https://github.com/mozilla/libaudit-go/issues/24
impl<T> Decoder for NetlinkCodec<NetlinkMessage<T>>
where
    T: NetlinkDeserializable<T> + Debug + Eq + PartialEq + Clone,
{
    type Item = NetlinkMessage<T>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        debug!("NetlinkCodec: decoding next message");

        loop {
            // If there's nothing to read, return Ok(None)
            if src.as_ref().is_empty() {
                trace!("buffer is empty");
                src.clear();
                return Ok(None);
            }

            // the uevent packets do not have any header
            let len = if self.ty == CodecType::UEventPacket {
                src.len()
            } else {
                // This is a bit hacky because we don't want to keep `src`
                // borrowed, since we need to mutate it later.
                let len_res = match NetlinkBuffer::new_checked(src.as_ref()) {
                    Ok(buf) => {
                        if self.ty == CodecType::Packet {
                            Ok(buf.length() as usize)
                        } else {
                            if (src.as_ref().len() as isize - buf.length() as isize) <= 16 {
                                // The audit messages are sometimes truncated,
                                // because the length specified in the header,
                                // does not take the header itself into
                                // account. To workaround this, we tweak the
                                // length. We've noticed two occurences of
                                // truncated packets:
                                //
                                // - the length of the header is not included (see also:
                                //   https://github.com/mozilla/libaudit-go/issues/24)
                                // - some rule message have some padding for alignment (see
                                //   https://github.com/linux-audit/audit-userspace/issues/78) which is not
                                //   taken into account in the buffer length.
                                warn!("found what looks like a truncated audit packet");
                                Ok(src.as_ref().len())
                            } else {
                                Ok(buf.length() as usize)
                            }
                        }
                    }
                    Err(e) => {
                        // We either received a truncated packet, or the
                        // packet if malformed (invalid length field). In
                        // both case, we can't decode the datagram, and we
                        // cannot find the start of the next one (if
                        // any). The only solution is to clear the buffer
                        // and potentially lose some datagrams.
                        error!("failed to decode datagram: {:?}: {:#x?}.", e, src.as_ref());
                        Err(())
                    }
                };

                if len_res.is_err() {
                    error!("clearing the whole socket buffer. Datagrams may have been lost");
                    src.clear();
                    return Ok(None);
                }

                len_res.unwrap()
            };

            let bytes = if self.ty == CodecType::AuditPacket {
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
            } else {
                src.split_to(len)
            };

            if self.ty == CodecType::UEventPacket {
                // dummy header, unused
                let header = NetlinkHeader::default();
                match T::deserialize(&header, &bytes) {
                    Ok(packet) => {
                        trace!("<<< {:?}", packet);
                        return Ok(Some(NetlinkMessage::new(
                            header,
                            NetlinkPayload::InnerMessage(packet),
                        )));
                    }
                    Err(e) => {
                        error!("failed to decode packet {:#x?}: {}", &bytes, e);
                    }
                }
            } else {
                let parsed = NetlinkMessage::<T>::deserialize(&bytes);
                match parsed {
                    Ok(packet) => {
                        trace!("<<< {:?}", packet);
                        return Ok(Some(packet));
                    }
                    Err(e) => {
                        error!("failed to decode packet {:#x?}: {}", &bytes, e);
                        // continue looping, there may be more datagrams in the buffer
                    }
                }
            };
        }
    }
}

impl<T> Encoder<NetlinkMessage<T>> for NetlinkCodec<NetlinkMessage<T>>
where
    T: Debug + Eq + PartialEq + Clone + NetlinkSerializable<T>,
{
    type Error = io::Error;

    fn encode(&mut self, msg: NetlinkMessage<T>, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let msg_len = msg.buffer_len();
        if buf.remaining_mut() < msg_len {
            // BytesMut can expand till usize::MAX... unlikely to hit this one.
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "message is {} bytes, but only {} bytes left in the buffer",
                    msg_len,
                    buf.remaining_mut()
                ),
            ));
        }

        // As NetlinkMessage::serialize needs an initialized buffer anyway
        // no need for any `unsafe` magic.
        let old_len = buf.len();
        let new_len = old_len + msg_len;
        buf.resize(new_len, 0);
        msg.serialize(&mut buf[old_len..][..msg_len]);
        trace!(">>> {:?}", msg);
        Ok(())
    }
}
