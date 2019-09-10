use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const TC_HEADER_LEN: usize = 20;

buffer!(TcBuffer, TC_HEADER_LEN);
fields!(TcBuffer {
    family: (u8, 0),
    pad1: (u8, 1),
    pad2: (u16, 2..4),
    index: (i32, 4..8),
    handle: (u32, 8..12),
    parent: (u32, 12..16),
    info: (u32, 16..20),
});

impl<'a, T: AsRef<[u8]> + ?Sized> TcBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[TC_HEADER_LEN..]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> TcBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[TC_HEADER_LEN..]
    }
}
