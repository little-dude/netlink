use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const ADDRESS_HEADER_LEN: usize = 8;

buffer!(AddressBuffer, ADDRESS_HEADER_LEN);
fields!(AddressBuffer {
    family: (u8, 0),
    prefix_len: (u8, 1),
    flags: (u8, 2),
    scope: (u8, 3),
    index: (u32, 4..8),
});

impl<'a, T: AsRef<[u8]> + ?Sized> AddressBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ADDRESS_HEADER_LEN..]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> AddressBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ADDRESS_HEADER_LEN..]
    }
}
