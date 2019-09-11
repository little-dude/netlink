use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const ROUTE_HEADER_LEN: usize = 12;

buffer!(RouteBuffer(ROUTE_HEADER_LEN) {
    address_family: (u8, 0),
    destination_length: (u8, 1),
    source_length: (u8, 2),
    tos: (u8, 2),
    table: (u8, 4),
    protocol: (u8, 5),
    scope: (u8, 6),
    kind: (u8, 7),
    flags: (u32, 8..ROUTE_HEADER_LEN),
    payload: (slice, ROUTE_HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized> RouteBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}
