use crate::{DecodeError, Index, NlaBuffer, NlasIterator, Rest};

const RTGEN_FAMILY: Index = 0;
// const PADDING: Field = 1..4;
const ATTRIBUTES: Rest = 4..;

pub const NSID_HEADER_LEN: usize = ATTRIBUTES.start;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NsIdBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NsIdBuffer<T> {
    pub fn new(buffer: T) -> NsIdBuffer<T> {
        NsIdBuffer { buffer }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn new_checked(buffer: T) -> Result<NsIdBuffer<T>, DecodeError> {
        let packet = Self::new(buffer);
        packet.check_buffer_length()?;
        Ok(packet)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < NSID_HEADER_LEN {
            Err(format!(
                "invalid NsIdBuffer: length is {} but NsIdBuffer are at least {} bytes",
                len, NSID_HEADER_LEN
            )
            .into())
        } else {
            Ok(())
        }
    }

    /// Return the rtgen family field
    pub fn rtgen_family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[RTGEN_FAMILY]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NsIdBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ATTRIBUTES]
    }

    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NsIdBuffer<&'a mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ATTRIBUTES]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NsIdBuffer<T> {
    /// set the rtgen family field
    pub fn set_rtgen_family(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[RTGEN_FAMILY] = value
    }
}
