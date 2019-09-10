use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const NEIGHBOUR_HEADER_LEN: usize = 12;
buffer!(NeighbourBuffer(NEIGHBOUR_HEADER_LEN) {
    family: (u8, 0),
    ifindex: (u32, 4..8),
    state: (u16, 8..10),
    flags: (u8, 10),
    ntype: (u8, 11),
});

impl<'a, T: AsRef<[u8]> + ?Sized> NeighbourBuffer<&'a T> {
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[NEIGHBOUR_HEADER_LEN..]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NeighbourBuffer<&'a mut T> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[NEIGHBOUR_HEADER_LEN..]
    }
}
