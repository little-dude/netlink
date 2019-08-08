use failure::ResultExt;

use crate::{
    nsid::{nlas::NsIdNla, NsIdBuffer, NsIdHeader},
    traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NsIdMessage {
    pub header: NsIdHeader,
    pub nlas: Vec<NsIdNla>,
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<NsIdMessage> for NsIdBuffer<&'buffer T> {
    fn parse(&self) -> Result<NsIdMessage, DecodeError> {
        Ok(NsIdMessage {
            header: self
                .parse()
                .context("failed to parse nsid message header")?,
            nlas: self.parse().context("failed to parse nsid message NLAs")?,
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<NsIdNla>> for NsIdBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<NsIdNla>, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}

impl Emitable for NsIdMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        message_types::{RTM_GETNSID, RTM_NEWNSID},
        nsid::nlas::NETNSA_NSID_NOT_ASSIGNED,
        traits::ParseableParametrized,
        RtnlBuffer, RtnlMessage,
    };
    use netlink_packet_core::NetlinkBuffer;

    #[rustfmt::skip]
    #[test]
    fn get_ns_id_request() {
        let data = vec![
            0x1c, 0x00, 0x00, 0x00, // length = 28
            0x5a, 0x00, // message type = 90 = RTM_GETNSID
            0x01, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // seq number
            0x00, 0x00, 0x00, 0x00, // pid

            // GETNSID message
            0x00, // rtgen family
            0x00, 0x00, 0x00, // padding
            // NLA
            0x08, 0x00, // length = 8
            0x03, 0x00, // type = 3 (Fd)
            0x04, 0x00, 0x00, 0x00 // 4
        ];
        let expected = RtnlMessage::GetNsId(NsIdMessage {
            header: NsIdHeader { rtgen_family: 0 },
            nlas: vec![NsIdNla::Fd(4)],
        });
        let actual = RtnlBuffer::new(&NetlinkBuffer::new(&data).payload())
            .parse_with_param(RTM_GETNSID)
            .unwrap();
        assert_eq!(expected, actual);
    }

    #[rustfmt::skip]
    #[test]
    fn get_ns_id_response() {
        let data = vec![
            0x1c, 0x00, 0x00, 0x00, // length = 28
            0x58, 0x00, // message type = RTM_NEWNSID
            0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // seq number
            0x76, 0x12, 0x00, 0x00, // pid

            // NETNSID message
            0x00, // rtgen family
            0x00, 0x00, 0x00, // padding
            // NLA
            0x08, 0x00, // length
            0x01, 0x00, // type = NETNSA_NSID
            0xff, 0xff, 0xff, 0xff // -1
        ];
        let expected = RtnlMessage::NewNsId(NsIdMessage {
            header: NsIdHeader { rtgen_family: 0 },
            nlas: vec![NsIdNla::Id(NETNSA_NSID_NOT_ASSIGNED)],
        });
        let actual = RtnlBuffer::new(&NetlinkBuffer::new(&data).payload())
            .parse_with_param(RTM_NEWNSID)
            .unwrap();
        assert_eq!(expected, actual);
    }
}
