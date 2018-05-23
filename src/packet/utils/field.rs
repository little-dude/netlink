use core::ops::{Range, RangeFrom};

pub type Field = Range<usize>;
pub type Rest = RangeFrom<usize>;
pub type Index = usize;

pub fn dynamic_field(start: usize, length: usize) -> Field {
    start..start + length
}
