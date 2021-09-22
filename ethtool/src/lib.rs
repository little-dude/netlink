mod connection;
mod error;
mod handle;
mod header;
mod macros;
mod message;
mod pause;

pub use connection::new_connection;
pub use error::EthtoolError;
pub use handle::EthtoolHandle;
pub use header::EthtoolHeader;
pub use message::{EthtoolAttr, EthtoolMessage};
pub use pause::{
    EthtoolPauseAttr,
    EthtoolPauseGetRequest,
    EthtoolPauseHandle,
    EthtoolPauseStatAttr,
};
