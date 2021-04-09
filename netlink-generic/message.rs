use anyhow::Context;
use netlink_packet_core::{
    DecodeError,
    NetlinkDeserializable,
    NetlinkHeader,
    NetlinkPayload,
    NetlinkSerializable,
};
use netlink_packet_utils::{
    nla::{DefaultNla, NlasIterator},
    Emitable,
    Parseable,
    ParseableParametrized,
};

use crate::{buffer::GENL_ID_CTRL, CtrlAttr, GenericNetlinkHeader, GenericNetlinkMessageBuffer};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum GenericNetlinkAttr {
    Ctrl(Vec<CtrlAttr>),
    Other(Vec<DefaultNla>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GenericNetlinkMessage {
    pub message_type: u16,
    pub header: GenericNetlinkHeader,
    pub nlas: GenericNetlinkAttr,
}

impl Emitable for GenericNetlinkMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len()
            + match &self.nlas {
                GenericNetlinkAttr::Ctrl(nlas) => nlas.as_slice().buffer_len(),
                GenericNetlinkAttr::Other(nlas) => nlas.as_slice().buffer_len(),
            }
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        match &self.nlas {
            GenericNetlinkAttr::Ctrl(nlas) => nlas
                .as_slice()
                .emit(&mut buffer[self.header.buffer_len()..]),
            GenericNetlinkAttr::Other(nlas) => nlas
                .as_slice()
                .emit(&mut buffer[self.header.buffer_len()..]),
        }
    }
}

impl NetlinkSerializable<GenericNetlinkMessage> for GenericNetlinkMessage {
    fn message_type(&self) -> u16 {
        self.message_type
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable<GenericNetlinkMessage> for GenericNetlinkMessage {
    type Error = DecodeError;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        let buf = GenericNetlinkMessageBuffer::new(payload);
        GenericNetlinkMessage::parse_with_param(&buf, header.message_type)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<GenericNetlinkMessageBuffer<&'a T>, u16>
    for GenericNetlinkMessage
{
    fn parse_with_param(
        buf: &GenericNetlinkMessageBuffer<&'a T>,
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        let header = GenericNetlinkHeader::parse(buf)
            .context("failed to parse generic netlink message header")?;

        match message_type {
            GENL_ID_CTRL => match GenericNetlinkMessageBuffer::new_checked(&buf.inner()) {
                Ok(buf) => Ok(GenericNetlinkMessage {
                    message_type,
                    header,
                    nlas: {
                        let mut nlas = Vec::new();
                        let error_msg = "failed to parse control message attributes";
                        for nla in NlasIterator::new(buf.payload()) {
                            let nla = &nla.context(error_msg)?;
                            let parsed = CtrlAttr::parse(nla).context(error_msg)?;
                            nlas.push(parsed);
                        }
                        GenericNetlinkAttr::Ctrl(nlas)
                    },
                }),
                Err(e) => Err(e),
            },
            _ => Err(format!("Unknown message type: {}", message_type).into()),
        }
    }
}

impl From<GenericNetlinkMessage> for NetlinkPayload<GenericNetlinkMessage> {
    fn from(message: GenericNetlinkMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
