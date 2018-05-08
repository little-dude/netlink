use super::Result;

pub trait Repr
where
    Self: Sized,
{
    /// Parse a packet and return a high-level representation.
    fn parse(buffer: &[u8]) -> Result<Self>;

    /// Return the length of a packet that will be emitted from this high-level representation.
    fn buffer_len(&self) -> usize;

    /// Emit a high-level representation into a buffer
    fn emit(&self, buffer: &mut [u8]) -> Result<()>;
}
