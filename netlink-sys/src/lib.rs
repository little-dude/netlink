use libc;

mod protocols;
pub use self::protocols::*;

mod sys;
pub use self::sys::*;

#[cfg(feature = "mio_support")]
extern crate mio as mio_crate;
#[cfg(feature = "mio_support")]
mod mio;

#[cfg(feature = "tokio_support")]
#[macro_use]
extern crate log;

#[cfg(feature = "tokio_support")]
#[macro_use]
extern crate futures;

#[cfg(feature = "tokio_support")]
mod tokio;
#[cfg(feature = "tokio_support")]
pub use self::tokio::*;

pub mod constants;
