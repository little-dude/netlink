mod error;
pub use self::error::*;

pub mod nla;

pub trait Emitable {
    fn buffer_len(&self) -> usize;
    fn emit(&self, buffer: &mut [u8]);
}

pub trait Parseable<T> {
    fn parse(&self) -> Result<T>;
}

mod field {
    use core::ops::{Range, RangeFrom};

    pub type Field = Range<usize>;
    pub type Rest = RangeFrom<usize>;
    pub type Index = usize;

    pub fn dynamic_field(start: usize, length: usize) -> Field {
        start..start + length
    }
}
pub use self::field::*;
