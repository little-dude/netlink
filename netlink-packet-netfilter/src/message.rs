// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError,
    NetlinkDeserializable,
    NetlinkHeader,
    NetlinkPayload,
    NetlinkSerializable,
};
use netlink_packet_utils::{buffer, nla::DefaultNla, Emitable, Parseable, ParseableParametrized};

use crate::{buffer::NetfilterBuffer, nflog::NfLogMessage};

pub const NETFILTER_HEADER_LEN: usize = 4;

buffer!(NetfilterHeaderBuffer(NETFILTER_HEADER_LEN) {
    family: (u8, 0),
    version: (u8, 1),
    res_id: (u16, 2..4),
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetfilterHeader {
    pub family: u8,
    pub version: u8,
    pub res_id: u16,
}

impl NetfilterHeader {
    pub fn new(family: u8, version: u8, res_id: u16) -> Self {
        Self {
            family,
            version,
            res_id,
        }
    }
}

impl Emitable for NetfilterHeader {
    fn buffer_len(&self) -> usize {
        NETFILTER_HEADER_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = NetfilterHeaderBuffer::new(buf);
        buf.set_family(self.family);
        buf.set_version(self.version);
        buf.set_res_id(self.res_id.to_be());
    }
}

impl<T: AsRef<[u8]>> Parseable<NetfilterHeaderBuffer<T>> for NetfilterHeader {
    fn parse(buf: &NetfilterHeaderBuffer<T>) -> Result<Self, DecodeError> {
        buf.check_buffer_length()?;
        Ok(NetfilterHeader {
            family: buf.family(),
            version: buf.version(),
            res_id: u16::from_be(buf.res_id()),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NetfilterMessageInner {
    NfLog(NfLogMessage),
    Other {
        subsys: u8,
        message_type: u8,
        nlas: Vec<DefaultNla>,
    },
}

impl From<NfLogMessage> for NetfilterMessageInner {
    fn from(message: NfLogMessage) -> Self {
        Self::NfLog(message)
    }
}

impl Emitable for NetfilterMessageInner {
    fn buffer_len(&self) -> usize {
        match self {
            NetfilterMessageInner::NfLog(message) => message.buffer_len(),
            NetfilterMessageInner::Other { nlas, .. } => nlas.as_slice().buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            NetfilterMessageInner::NfLog(message) => message.emit(buffer),
            NetfilterMessageInner::Other { nlas, .. } => nlas.as_slice().emit(buffer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]

pub struct NetfilterMessage {
    pub header: NetfilterHeader,
    pub inner: NetfilterMessageInner,
}

impl NetfilterMessage {
    pub fn new<T: Into<NetfilterMessageInner>>(header: NetfilterHeader, inner: T) -> Self {
        Self {
            header,
            inner: inner.into(),
        }
    }

    pub fn subsys(&self) -> u8 {
        match self.inner {
            NetfilterMessageInner::NfLog(_) => NfLogMessage::SUBSYS,
            NetfilterMessageInner::Other { subsys, .. } => subsys,
        }
    }

    pub fn message_type(&self) -> u8 {
        match self.inner {
            NetfilterMessageInner::NfLog(ref message) => message.message_type(),
            NetfilterMessageInner::Other { message_type, .. } => message_type,
        }
    }
}

impl Emitable for NetfilterMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.inner.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.inner.emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl NetlinkSerializable for NetfilterMessage {
    fn message_type(&self) -> u16 {
        ((self.subsys() as u16) << 8) | self.message_type() as u16
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable for NetfilterMessage {
    type Error = DecodeError;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        match NetfilterBuffer::new_checked(payload) {
            Err(e) => Err(e),
            Ok(buffer) => match NetfilterMessage::parse_with_param(&buffer, header.message_type) {
                Err(e) => Err(e),
                Ok(message) => Ok(message),
            },
        }
    }
}

impl From<NetfilterMessage> for NetlinkPayload<NetfilterMessage> {
    fn from(message: NetfilterMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
