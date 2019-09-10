use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const NEIGHBOUR_TABLE_HEADER_LEN: usize = 4;

buffer!(NeighbourTableBuffer(NEIGHBOUR_TABLE_HEADER_LEN) {
    family: (u8, 0),
});

impl<'a, T: AsRef<[u8]> + ?Sized> NeighbourTableBuffer<&'a T> {
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[NEIGHBOUR_TABLE_HEADER_LEN..]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NeighbourTableBuffer<&'a mut T> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[NEIGHBOUR_TABLE_HEADER_LEN..]
    }
}
