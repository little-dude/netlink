// SPDX-License-Identifier: MIT

mod attr;
mod channel;
mod connection;
mod error;
mod handle;
mod iface;
mod macros;
mod message;
mod stats;

pub use attr::Nl80211Attr;
pub use channel::Nl80211WiPhyChannelType;
#[cfg(feature = "tokio_socket")]
pub use connection::new_connection;
pub use connection::new_connection_with_socket;
pub use error::Nl80211Error;
pub use handle::Nl80211Handle;
pub use iface::{Nl80211InterfaceGetRequest, Nl80211InterfaceHandle, Nl80211InterfaceType};
pub use message::{Nl80211Cmd, Nl80211Message};
pub use stats::Nl80211TransmitQueueStat;

pub(crate) use handle::nl80211_execute;
