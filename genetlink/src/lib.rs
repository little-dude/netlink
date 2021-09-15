#[macro_use]
extern crate thiserror;

mod connection;
mod error;
mod handle;
pub mod message;
mod resolver;

pub use connection::new_connection;
pub use error::GenetlinkError;
pub use handle::GenetlinkHandle;
