//! obtaining information about sockets

mod buffer;
mod raw;

pub use self::raw::{sk_meminfo as SkMemInfo, SOCK_DIAG_BY_FAMILY};
