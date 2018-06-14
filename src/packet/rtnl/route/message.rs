use super::{RouteBuffer, RouteHeader, RouteNla};
use {Emitable, Parseable, Result};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteMessage {
    pub header: RouteHeader,
    pub nlas: Vec<RouteNla>,
}

impl Emitable for RouteMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<RouteMessage> for RouteBuffer<&'buffer T> {
    fn parse(&self) -> Result<RouteMessage> {
        Ok(RouteMessage {
            header: self.parse()?,
            nlas: self.parse()?,
        })
    }
}

// FIXME: we should make it possible to provide a "best effort" parsing method. Right now, if we
// fail on a single nla, we return an error. Maybe we could have another impl that returns
// Vec<Result<RouteNla>>.
impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<RouteNla>> for RouteBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<RouteNla>> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}
