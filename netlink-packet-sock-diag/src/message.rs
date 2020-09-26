use crate::{
    inet,
    traits::{Emitable, ParseableParametrized},
    unix, DecodeError, NetlinkDeserializable, NetlinkHeader, NetlinkPayload, NetlinkSerializable,
    SockDiagBuffer, SOCK_DIAG_BY_FAMILY,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SockDiagMessage {
    InetRequest(inet::InetRequest),
    InetResponse(inet::InetResponse),
    UnixRequest(unix::UnixRequest),
    UnixResponse(unix::UnixResponse),
}

impl SockDiagMessage {
    pub fn is_inet_request(&self) -> bool {
        if let SockDiagMessage::InetRequest(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_inet_response(&self) -> bool {
        if let SockDiagMessage::InetResponse(_) = *self {
            true
        } else {
            false
        }
    }
    pub fn is_unix_request(&self) -> bool {
        if let SockDiagMessage::UnixRequest(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_unix_response(&self) -> bool {
        if let SockDiagMessage::UnixResponse(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn message_type(&self) -> u16 {
        SOCK_DIAG_BY_FAMILY
    }
}

impl Emitable for SockDiagMessage {
    fn buffer_len(&self) -> usize {
        use SockDiagMessage::*;

        match self {
            InetRequest(ref msg) => msg.buffer_len(),
            InetResponse(ref msg) => msg.buffer_len(),
            UnixRequest(ref msg) => msg.buffer_len(),
            UnixResponse(ref msg) => msg.buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        use SockDiagMessage::*;

        match self {
            InetRequest(ref msg) => msg.emit(buffer),
            InetResponse(ref msg) => msg.emit(buffer),
            UnixRequest(ref msg) => msg.emit(buffer),
            UnixResponse(ref msg) => msg.emit(buffer),
        }
    }
}

impl NetlinkSerializable<SockDiagMessage> for SockDiagMessage {
    fn message_type(&self) -> u16 {
        self.message_type()
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable<SockDiagMessage> for SockDiagMessage {
    type Error = DecodeError;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        let buffer = SockDiagBuffer::new_checked(&payload)?;
        Ok(SockDiagMessage::parse_with_param(
            &buffer,
            header.message_type,
        )?)
    }
}

impl From<SockDiagMessage> for NetlinkPayload<SockDiagMessage> {
    fn from(message: SockDiagMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
