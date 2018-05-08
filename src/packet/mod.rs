pub mod field {
    use core::ops;
    pub type Field = ops::Range<usize>;
    pub type Rest = ops::RangeFrom<usize>;
    pub type Index = usize;

    pub fn dynamic_field(start: usize, length: usize) -> Field {
        start..start + length
    }
}

#[macro_use]
mod macros;
mod error;
mod flags;
mod repr;

pub use self::error::{Error, Result};
pub use self::flags::Flags;
pub use self::repr::Repr;

mod header;
pub use self::header::{MessageType, Packet};

pub mod attribute;
pub mod link;
