use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const NSID_HEADER_LEN: usize = 4;

buffer!(NsIdBuffer, NSID_HEADER_LEN);
fields!(NsIdBuffer {
    rtgen_family: (u8, 0),
});

impl<'a, T: AsRef<[u8]> + ?Sized> NsIdBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[4..]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NsIdBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[4..]
    }
}
