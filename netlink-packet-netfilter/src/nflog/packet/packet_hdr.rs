use netlink_packet_core::DecodeError;
use netlink_packet_utils::{buffer, nla::Nla, Parseable};

const PACKET_HDR_LEN: usize = 4;
pub const NFULA_PACKET_HDR: u16 = libc::NFULA_PACKET_HDR as u16;

buffer!(PacketHdrBuffer(PACKET_HDR_LEN) {
    hw_protocol: (u16, 0..2),
    hook: (u8, 2),
    pad: (u8, 3),
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHdr {
    hw_protocol: u16,
    hook: u8,
}

impl Nla for PacketHdr {
    fn value_len(&self) -> usize {
        PACKET_HDR_LEN
    }

    fn kind(&self) -> u16 {
        NFULA_PACKET_HDR
    }

    fn emit_value(&self, buf: &mut [u8]) {
        let mut buf = PacketHdrBuffer::new(buf);
        buf.set_hw_protocol(self.hw_protocol.to_be());
        buf.set_hook(self.hook)
    }
}

impl<T: AsRef<[u8]>> Parseable<PacketHdrBuffer<T>> for PacketHdr {
    fn parse(buf: &PacketHdrBuffer<T>) -> Result<Self, DecodeError> {
        Ok(PacketHdr {
            hw_protocol: u16::from_be(buf.hw_protocol()),
            hook: buf.hook(),
        })
    }
}
