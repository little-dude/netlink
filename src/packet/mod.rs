pub(crate) mod field {
    use core::ops;
    pub type Field = ops::Range<usize>;
    pub type Rest = ops::RangeFrom<usize>;
    pub type Index = usize;

    pub fn dynamic_field(start: usize, length: usize) -> Field {
        start..start + length
    }
}

mod error;
mod flags;

pub use self::error::{Error, Result};
pub use self::flags::*;

mod message_type;
pub use self::message_type::*;

mod header;
pub use self::header::*;

mod nla;
pub use self::nla::*;
pub mod link;
