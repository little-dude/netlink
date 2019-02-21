//! obtaining information about sockets

mod buffer;
mod raw;

pub use self::buffer::States;
pub use self::raw::{sk_meminfo as SkMemInfo, state as State, SOCK_DIAG_BY_FAMILY};
