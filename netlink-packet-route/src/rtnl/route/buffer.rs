use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const ROUTE_HEADER_LEN: usize = 12;

buffer!(RouteBuffer, ROUTE_HEADER_LEN);
fields!(RouteBuffer {
    address_family: (u8, 0),
    destination_length: (u8, 1),
    source_length: (u8, 2),
    tos: (u8, 2),
    table: (u8, 4),
    protocol: (u8, 5),
    scope: (u8, 6),
    kind: (u8, 7),
    flags: (u32, 8..12),
});

impl<'a, T: AsRef<[u8]> + ?Sized> RouteBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[12..]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> RouteBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[12..]
    }
}
