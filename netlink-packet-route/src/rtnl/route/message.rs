use crate::{
    nlas::route::Nla,
    traits::{Emitable, Parseable},
    DecodeError, RouteHeader, RouteMessageBuffer,
};
use failure::ResultExt;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct RouteMessage {
    pub header: RouteHeader,
    pub nlas: Vec<Nla>,
}

impl Emitable for RouteMessage {
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

impl<'a, T: AsRef<[u8]> + 'a> Parseable<RouteMessageBuffer<&'a T>> for RouteMessage {
    fn parse(buf: &RouteMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(RouteMessage {
            header: RouteHeader::parse(buf).context("failed to parse route message header")?,
            nlas: Vec::<Nla>::parse(buf).context("failed to parse route message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<RouteMessageBuffer<&'a T>> for Vec<Nla> {
    fn parse(buf: &RouteMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
