use crate::buffer::GenlBuffer;
use crate::header::GenlHeader;
use crate::traits::*;
use netlink_packet_core::{
    DecodeError, NetlinkDeserializable, NetlinkHeader, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_utils::{Emitable, ParseableParametrized};
use std::fmt::Debug;

/// Represent the generic netlink messages
///
/// This type can wrap data types `F` which represents a generic family payload.
/// The message can be serialize/deserialize if the type `F` implements [`GenlFamily`],
/// [`Emitable`], and [`ParseableParametrized<[u8], GenlHeader>`](ParseableParametrized).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenlMessage<F>
where
    F: Clone + Debug + PartialEq + Eq,
{
    pub header: GenlHeader,
    pub payload: F,
}

impl<F> Emitable for GenlMessage<F>
where
    F: GenlFamily + Emitable + Clone + Debug + PartialEq + Eq,
{
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.payload.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);

        let buffer = &mut buffer[self.header.buffer_len()..];
        self.payload.emit(buffer);
    }
}

impl<F> NetlinkSerializable<GenlMessage<F>> for GenlMessage<F>
where
    F: GenlFamily + Emitable + Clone + Debug + PartialEq + Eq,
{
    fn message_type(&self) -> u16 {
        self.payload.family_id()
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl<'a, F> NetlinkDeserializable<GenlMessage<F>> for GenlMessage<F>
where
    F: ParseableParametrized<[u8], GenlHeader> + Clone + Debug + PartialEq + Eq,
{
    type Error = DecodeError;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        let buffer = GenlBuffer::new_checked(payload)?;
        GenlMessage::parse_with_param(&buffer, header.message_type)
    }
}

impl<F> From<GenlMessage<F>> for NetlinkPayload<GenlMessage<F>>
where
    F: Clone + Debug + PartialEq + Eq,
{
    fn from(message: GenlMessage<F>) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
