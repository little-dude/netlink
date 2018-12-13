use failure::ResultExt;

use super::{TcBuffer, TcNla};
use crate::{DecodeError, Emitable, Parseable, TC_HEADER_LEN};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcMessage {
    header: TcHeader,
    nlas: Vec<TcNla>,
}

impl TcMessage {
    pub fn new() -> Self {
        TcMessage::from_parts(TcHeader::new(), vec![])
    }

    pub fn into_parts(self) -> (TcHeader, Vec<TcNla>) {
        (self.header, self.nlas)
    }

    pub fn header_mut(&mut self) -> &mut TcHeader {
        &mut self.header
    }

    pub fn header(&self) -> &TcHeader {
        &self.header
    }

    pub fn nlas(&self) -> &[TcNla] {
        self.nlas.as_slice()
    }

    pub fn nlas_mut(&mut self) -> &mut Vec<TcNla> {
        &mut self.nlas
    }

    pub fn append_nla(&mut self, nla: TcNla) {
        self.nlas.push(nla)
    }

    pub fn from_parts(header: TcHeader, nlas: Vec<TcNla>) -> Self {
        TcMessage { header, nlas }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcHeader {
    family: u8,
    // Interface index
    index: i32,
    // Qdisc handle
    handle: u32,
    // Parent Qdisc
    parent: u32,
    info: u32,
}

impl Default for TcHeader {
    fn default() -> Self {
        TcHeader::new()
    }
}

impl TcHeader {
    pub fn new() -> Self {
        TcHeader {
            family: 0,
            index: 0,
            handle: 0,
            parent: 0,
            info: 0,
        }
    }
}

impl Emitable for TcHeader {
    fn buffer_len(&self) -> usize {
        TC_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = TcBuffer::new(buffer);
        packet.set_family(self.family);
        packet.set_index(self.index);
        packet.set_handle(self.handle);
        packet.set_parent(self.parent);
        packet.set_info(self.info);
    }
}

impl Emitable for TcMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<T: AsRef<[u8]>> Parseable<TcHeader> for TcBuffer<T> {
    fn parse(&self) -> Result<TcHeader, DecodeError> {
        Ok(TcHeader {
            family: self.family(),
            index: self.index(),
            handle: self.handle(),
            parent: self.parent(),
            info: self.info(),
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<TcMessage> for TcBuffer<&'buffer T> {
    fn parse(&self) -> Result<TcMessage, DecodeError> {
        Ok(TcMessage {
            header: self.parse().context("failed to parse tc message header")?,
            nlas: self.parse().context("failed to parse tc message NLAs")?,
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<TcNla>> for TcBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<TcNla>, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}
