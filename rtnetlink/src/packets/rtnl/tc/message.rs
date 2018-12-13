use super::{TcBuffer, TcNla};
use {Emitable, Parseable, Result, TC_HEADER_LEN};

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
    pad1: u8,
    pad2: u16,
    index: i32,
    handle: u32,
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
            pad1: 0,
            pad2: 0,
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
        // in rust, we're guaranteed that when doing `a() + b(), a() is evaluated first
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<T: AsRef<[u8]>> Parseable<TcHeader> for TcBuffer<T> {
    fn parse(&self) -> Result<TcHeader> {
        Ok(TcHeader {
            family: self.family(),
            pad1: self.pad1(),
            pad2: self.pad2(),
            index: self.index(),
            handle: self.handle(),
            parent: self.parent(),
            info: self.info(),
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<TcMessage> for TcBuffer<&'buffer T> {
    fn parse(&self) -> Result<TcMessage> {
        let header = self.parse()?;
        let parsed_nlas: Vec<Result<TcNla>> = self.parse()?;
        let (valid_nlas, parse_errors): (Vec<_>, Vec<_>) =
            parsed_nlas.into_iter().partition(Result::is_ok);
        let nlas = valid_nlas.into_iter().map(Result::unwrap).collect();
        // FIXME: perhaps there should be a way to access the error(s) after the message is ready?
        for parse_result in parse_errors {
            warn!(
                "Failed to parse a Netlink TC message attribute: {}",
                parse_result.unwrap_err()
            );
        }
        Ok(TcMessage { header, nlas })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<Result<TcNla>>> for TcBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<Result<TcNla>>> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf.and_then(|nla_buf| nla_buf.parse()));
        }
        Ok(nlas)
    }
}
