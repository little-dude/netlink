use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const LINK_HEADER_LEN: usize = 16;

buffer!(LinkBuffer, 16);
fields!(LinkBuffer {
    interface_family: (u8, 0),
    reserved_1: (u8, 1),
    link_layer_type: (u16, 2..4),
    link_index: (u32, 4..8),
    flags: (u32, 8..12),
    change_mask: (u32, 12..16),
});

impl<'a, T: AsRef<[u8]> + ?Sized> LinkBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[LINK_HEADER_LEN..]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> LinkBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[LINK_HEADER_LEN..]
    }
}
