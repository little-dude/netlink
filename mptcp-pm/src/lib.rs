// SPDX-License-Identifier: MIT

mod address;
mod connection;
mod error;
mod handle;
mod limits;
mod macros;
mod message;

pub use address::{
    MptcpPathManagerAddressAttr,
    MptcpPathManagerAddressAttrFlag,
    MptcpPathManagerAddressGetRequest,
    MptcpPathManagerAddressHandle,
};
#[cfg(feature = "tokio_socket")]
pub use connection::new_connection;
pub use connection::new_connection_with_socket;
pub use error::MptcpPathManagerError;
pub use handle::MptcpPathManagerHandle;
pub use limits::{
    MptcpPathManagerLimitsAttr,
    MptcpPathManagerLimitsGetRequest,
    MptcpPathManagerLimitsHandle,
};
pub use message::{MptcpPathManagerAttr, MptcpPathManagerCmd, MptcpPathManagerMessage};

pub(crate) use handle::mptcp_execute;
