use netlink_packet_utils::{DecodeError, Emitable, Parseable};

use crate::{buffer::GENL_HEADER_LEN, GenericNetlinkMessageBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct GenericNetlinkHeader {
    pub cmd: u8,
    pub version: u8,
    // there is an u16 reserverd in kernel `struct genlmsghdr`
}

impl Emitable for GenericNetlinkHeader {
    fn buffer_len(&self) -> usize {
        GENL_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = GenericNetlinkMessageBuffer::new(buffer);
        packet.set_cmd(self.cmd);
        packet.set_version(self.version);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<GenericNetlinkMessageBuffer<&'a T>>
    for GenericNetlinkHeader
{
    fn parse(buf: &GenericNetlinkMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(GenericNetlinkHeader {
            cmd: buf.cmd(),
            version: buf.version(),
        })
    }
}
