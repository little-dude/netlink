use packet::common::Error;
use packet::NetlinkBuffer;

use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder};

impl Decoder for NetlinkBuffer<Vec<u8>> {
    type Item = NetlinkBuffer<Vec<u8>>;
    type Error = Error;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let len = match NetlinkBuffer::new_checked(src.as_ref()) {
            Ok(buf) => buf.length() as usize,
            Err(Error::Truncated) => return Ok(None),
            Err(e) => panic!("Unknown error while reading packet: {}", e),
        };
        let bytes = src.split_to(len);
        return Ok(Some(NetlinkBuffer::new(bytes.to_vec())));
    }
}

impl<T: AsRef<[u8]>> Encoder for NetlinkBuffer<T> {
    type Item = NetlinkBuffer<T>;
    type Error = Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.extend_from_slice(msg.into_inner().as_ref());
        Ok(())
    }
}
