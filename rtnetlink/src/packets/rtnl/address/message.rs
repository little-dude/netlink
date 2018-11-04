use super::{AddressBuffer, AddressNla};
use {Emitable, Parseable, Result, ADDRESS_HEADER_LEN};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AddressMessage {
    pub header: AddressHeader,
    pub nlas: Vec<AddressNla>,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AddressHeader {
    pub family: u8,
    pub prefix_len: u8,
    pub flags: u8,
    pub scope: u8,
    pub index: u32,
}

impl Emitable for AddressHeader {
    fn buffer_len(&self) -> usize {
        ADDRESS_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = AddressBuffer::new(buffer);
        packet.set_family(self.family);
        packet.set_prefix_len(self.prefix_len);
        packet.set_flags(self.flags);
        packet.set_scope(self.scope);
        packet.set_index(self.index);
    }
}

impl Emitable for AddressMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        // in rust, we're guaranteed that when doing `a() + b(), a() is evaluated first
        self.header.emit(buffer);
        self.nlas.as_slice().emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl<T: AsRef<[u8]>> Parseable<AddressHeader> for AddressBuffer<T> {
    fn parse(&self) -> Result<AddressHeader> {
        Ok(AddressHeader {
            family: self.family(),
            prefix_len: self.prefix_len(),
            flags: self.flags(),
            scope: self.scope(),
            index: self.index(),
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<AddressMessage> for AddressBuffer<&'buffer T> {
    fn parse(&self) -> Result<AddressMessage> {
        Ok(AddressMessage {
            header: self.parse()?,
            nlas: self.parse()?,
        })
    }
}

// FIXME: we should make it possible to provide a "best effort" parsing method. Right now, if we
// fail on a single nla, we return an error. Maybe we could have another impl that returns
// Vec<Result<Address>>.
impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<Vec<AddressNla>> for AddressBuffer<&'buffer T> {
    fn parse(&self) -> Result<Vec<AddressNla>> {
        let mut nlas = vec![];
        for nla_buf in self.nlas() {
            nlas.push(nla_buf?.parse()?);
        }
        Ok(nlas)
    }
}
