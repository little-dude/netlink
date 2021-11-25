// SPDX-License-Identifier: MIT

use std::{fmt::Debug, io};

use bytes::{BufMut, BytesMut};
use netlink_packet_core::{
    NetlinkBuffer,
    NetlinkDeserializable,
    NetlinkMessage,
    NetlinkSerializable,
};

/// Protocol to serialize and deserialize messages to and from datagrams
///
/// This is separate from `tokio_util::codec::{Decoder, Encoder}` as the implementations
/// rely on the buffer containing full datagrams; they won't work well with simple
/// bytestreams.
///
/// Officially there should be exactly one implementation of this, but the audit
/// subsystem ignores way too many rules of the protocol, so they need a separate
/// implementation.
///
/// Although one could make a tighter binding between `NetlinkMessageCodec` and
/// the message types (NetlinkDeserializable+NetlinkSerializable) it can handle,
/// this would put quite some overhead on subsystems that followed the spec - so
/// we simply default to the proper implementation (in `Connection`) and the
/// `audit` code needs to overwrite it.
pub trait NetlinkMessageCodec {
    /// Decode message of given type from datagram payload
    ///
    /// There might be more than one message; this needs to be called until it
    /// either returns `Ok(None)` or an error.
    fn decode<T>(src: &mut BytesMut) -> io::Result<Option<NetlinkMessage<T>>>
    where
        T: NetlinkDeserializable + Debug;

    /// Encode message to (datagram) buffer
    fn encode<T>(msg: NetlinkMessage<T>, buf: &mut BytesMut) -> io::Result<()>
    where
        T: NetlinkSerializable + Debug;
}

fn pad_msg_len(len: usize) -> Result<usize, io::Error> {
    // whether payload len or "full" message len: both use the same alignment
    // also note that the header size is already aligned.
    const ALIGN_TO: usize = 4; // power of two!
    match len.checked_add(ALIGN_TO - 1) {
        Some(len) => Ok(len & !(ALIGN_TO - 1)),
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "message is {} bytes long; can't add padding without overflow",
                len,
            ),
        )),
    }
}

/// Standard implementation of `NetlinkMessageCodec`
pub struct NetlinkCodec {
    // we don't need an instance of this, just the type
    _private: (),
}

impl NetlinkMessageCodec for NetlinkCodec {
    fn decode<T>(src: &mut BytesMut) -> io::Result<Option<NetlinkMessage<T>>>
    where
        T: NetlinkDeserializable + Debug,
    {
        debug!("NetlinkCodec: decoding next message");

        loop {
            // If there's nothing to read, return Ok(None)
            if src.as_ref().is_empty() {
                trace!("buffer is empty");
                src.clear();
                return Ok(None);
            }

            // This is a bit hacky because we don't want to keep `src`
            // borrowed, since we need to mutate it later.
            let len_res = match NetlinkBuffer::new_checked(src.as_ref()) {
                Ok(buf) => Ok(buf.length() as usize),
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

            let len = len_res.unwrap();
            // skip padding, but only if present in buffer. assumes no partial datagrams in buffer...
            // (i.e. this is a problem if the padding is received later)
            let padded_len = std::cmp::min(pad_msg_len(len)?, src.len());

            // split off `padded_len` bytes, but we only use `len` bytes
            let mut bytes = src.split_to(padded_len);
            bytes.truncate(len);

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
        }
    }

    fn encode<T>(msg: NetlinkMessage<T>, buf: &mut BytesMut) -> io::Result<()>
    where
        T: Debug + NetlinkSerializable,
    {
        let msg_len = msg.buffer_len();
        let padded_msg_len = pad_msg_len(msg_len)?;
        if buf.remaining_mut() < padded_msg_len {
            // BytesMut can expand till usize::MAX... unlikely to hit this one.
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "padded message is {} bytes, but only {} bytes left in the buffer",
                    padded_msg_len,
                    buf.remaining_mut()
                ),
            ));
        }

        // As NetlinkMessage::serialize needs an initialized buffer anyway
        // no need for any `unsafe` magic.
        let old_len = buf.len();
        let new_len = old_len + padded_msg_len;
        buf.resize(new_len, 0);
        msg.serialize(&mut buf[old_len..][..msg_len]);
        trace!(">>> {:?}", msg);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{NetlinkCodec, NetlinkMessageCodec};
    use bytes::BytesMut;
    use netlink_packet_core::{
        NetlinkDeserializable,
        NetlinkHeader,
        NetlinkMessage,
        NetlinkPayload,
        NetlinkSerializable,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum MsgNever {}

    impl NetlinkSerializable for MsgNever {
        fn message_type(&self) -> u16 {
            match *self {}
        }

        fn buffer_len(&self) -> usize {
            match *self {}
        }

        fn serialize(&self, _buffer: &mut [u8]) {
            match *self {}
        }
    }

    impl NetlinkDeserializable for MsgNever {
        type Error = std::io::Error;

        fn deserialize(_header: &NetlinkHeader, _payload: &[u8]) -> Result<MsgNever, Self::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MsgNever can't ever be a payload",
            ))
        }
    }

    fn overrun_msg_with_len(len: usize) -> NetlinkMessage<MsgNever> {
        let mut buf = Vec::new();
        buf.resize(len, 0xff);
        let mut msg = NetlinkMessage {
            header: Default::default(),
            payload: NetlinkPayload::Overrun(buf),
        };
        msg.finalize();
        msg
    }

    fn encode_with_prefix<D>(prefix_len: usize, data: NetlinkMessage<D>) -> BytesMut
    where
        D: NetlinkSerializable + std::fmt::Debug,
    {
        let mut buf = BytesMut::new();
        // for now encoder doesn't require buffer to be "pre-aligned"; allow this
        // to be tested by different (unaligned) "prefixes"
        buf.resize(prefix_len, 0x7f);
        NetlinkCodec::encode(data, &mut buf).unwrap();
        buf
    }

    fn test_decode(raw: &[u8], mut msgs: &[NetlinkMessage<MsgNever>]) {
        // if we need to see decode errors we could use this ugly log initializiation:
        // let _ = env_logger::try_init();
        let mut buf = BytesMut::from(raw);
        loop {
            if let Some(msg) = NetlinkCodec::decode::<MsgNever>(&mut buf).unwrap() {
                assert!(
                    !msgs.is_empty(),
                    "Got more messages than expected: {:?}",
                    msg
                );
                assert_eq!(msg, msgs[0]);
                msgs = &msgs[1..];
            } else {
                assert!(msgs.is_empty(), "Missing messages: {:?}", msgs);
                break;
            }
        }
    }

    fn test_single_encode(
        prefix_len: usize,
        data: NetlinkMessage<MsgNever>,
        expected_msg_len: usize,
    ) {
        let result = encode_with_prefix(prefix_len, data.clone());
        assert_eq!(result.len(), prefix_len + expected_msg_len,);
        test_decode(&result[prefix_len..], &[data]);
    }

    #[test]
    fn test_encoding_unaligned1() {
        test_single_encode(
            7,
            overrun_msg_with_len(1),
            16 /* header */ + 4, /* padded data */
        );
    }

    #[test]
    fn test_encoding_unaligned2() {
        test_single_encode(
            7,
            overrun_msg_with_len(2),
            16 /* header */ + 4, /* padded data */
        );
    }

    #[test]
    fn test_encoding_unaligned3() {
        test_single_encode(
            7,
            overrun_msg_with_len(3),
            16 /* header */ + 4, /* padded data */
        );
    }

    #[test]
    fn test_encoding_unaligned4() {
        test_single_encode(
            7,
            overrun_msg_with_len(4),
            16 /* header */ + 4, /* padded data */
        );
    }

    fn encode_batch_with_prefix<D>(prefix_len: usize, data: Vec<NetlinkMessage<D>>) -> BytesMut
    where
        D: NetlinkSerializable + std::fmt::Debug,
    {
        let mut buf = BytesMut::new();
        // for now encoder doesn't require buffer to be "pre-aligned"; allow this
        // to be tested by different (unaligned) "prefixes"
        buf.resize(prefix_len, 0x7f);
        for frame in data {
            NetlinkCodec::encode(frame, &mut buf).unwrap();
        }
        buf
    }

    fn test_batch_encode(
        prefix_len: usize,
        data: Vec<NetlinkMessage<MsgNever>>,
        expected_msg_len: usize,
    ) {
        let result = encode_batch_with_prefix(prefix_len, data.clone());
        assert_eq!(result.len(), prefix_len + expected_msg_len,);
        test_decode(&result[prefix_len..], &data);
    }

    #[test]
    fn test_batch_encoding_unaligned1() {
        test_batch_encode(
            1,
            vec![overrun_msg_with_len(1), overrun_msg_with_len(4)],
            2 * 16 + 2 * 4,
        );
    }

    #[test]
    fn test_batch_encoding_unaligned2() {
        test_batch_encode(
            1,
            vec![overrun_msg_with_len(2), overrun_msg_with_len(4)],
            2 * 16 + 2 * 4,
        );
    }

    #[test]
    fn test_batch_encoding_unaligned3() {
        test_batch_encode(
            1,
            vec![overrun_msg_with_len(3), overrun_msg_with_len(4)],
            2 * 16 + 2 * 4,
        );
    }

    #[test]
    fn test_batch_encoding_unaligned4() {
        test_batch_encode(
            1,
            vec![overrun_msg_with_len(4), overrun_msg_with_len(4)],
            2 * 16 + 2 * 4,
        );
    }
}
