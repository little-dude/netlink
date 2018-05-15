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
mod repr;

pub use self::error::{Error, Result};
pub use self::flags::Flags;
pub use self::repr::Repr;

mod message_type;
pub use self::message_type::MessageType;

mod header;
pub use self::header::Packet;

pub mod attribute;
pub mod link;
