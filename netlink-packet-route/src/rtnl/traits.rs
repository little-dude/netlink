use crate::DecodeError;

/// A type that implements `Emitable` can be serialized.
pub trait Emitable {
    /// Return the length of the serialized data.
    fn buffer_len(&self) -> usize;

    /// Serialize this types and write the serialized data into the given buffer.
    ///
    /// # Panic
    ///
    /// This method panic if the buffer is not big enough. You **must** make sure the buffer is big
    /// enough before calling this method. You can use
    /// [`buffer_len()`](trait.Emitable.html#method.buffer_len) to check how big the storage needs
    /// to be.
    fn emit(&self, buffer: &mut [u8]);
}

/// A `Parseable` type can be used to deserialize data into the target type `T` for which it is
/// implemented.
pub trait Parseable<T> {
    /// Deserialize the current type.
    fn parse(&self) -> Result<T, DecodeError>;
}

/// A `Parseable` type can be used to deserialize data into the target type `T` for which it is
/// implemented.
pub trait ParseableParametrized<T, P> {
    /// Deserialize the current type.
    fn parse_with_param(&self, params: P) -> Result<T, DecodeError>;
}
