use crate::{
    buffer::NetfilterBuffer,
    constants::{NFNL_SUBSYS_ULOG, NFULNL_MSG_CONFIG, NFULNL_MSG_PACKET},
    nflog::nlas::{config::ConfigNla, packet::PacketNla},
    nla::DefaultNla,
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NfLogMessage {
    Config(Vec<ConfigNla>),
    Packet(Vec<PacketNla>),
    Other {
        message_type: u8,
        nlas: Vec<DefaultNla>,
    },
}

impl NfLogMessage {
    pub const SUBSYS: u8 = NFNL_SUBSYS_ULOG;

    pub fn message_type(&self) -> u8 {
        match self {
            NfLogMessage::Config(_) => NFULNL_MSG_CONFIG,
            NfLogMessage::Packet(_) => NFULNL_MSG_PACKET,
            NfLogMessage::Other { message_type, .. } => *message_type,
        }
    }
}

impl Emitable for NfLogMessage {
    fn buffer_len(&self) -> usize {
        match self {
            NfLogMessage::Config(nlas) => nlas.as_slice().buffer_len(),
            NfLogMessage::Packet(nlas) => nlas.as_slice().buffer_len(),
            NfLogMessage::Other { nlas, .. } => nlas.as_slice().buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            NfLogMessage::Config(nlas) => nlas.as_slice().emit(buffer),
            NfLogMessage::Packet(nlas) => nlas.as_slice().emit(buffer),
            NfLogMessage::Other { nlas, .. } => nlas.as_slice().emit(buffer),
        };
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<NetfilterBuffer<&'a T>, u8>
    for NfLogMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match message_type {
            NFULNL_MSG_CONFIG => {
                let nlas = buf.parse_all_nlas(|nla_buf| ConfigNla::parse(&nla_buf))?;
                NfLogMessage::Config(nlas)
            }
            NFULNL_MSG_PACKET => {
                let nlas = buf.parse_all_nlas(|nla_buf| PacketNla::parse(&nla_buf))?;
                NfLogMessage::Packet(nlas)
            }
            _ => NfLogMessage::Other {
                message_type,
                nlas: buf.default_nlas()?,
            },
        })
    }
}
