//! obtaining information about sockets
//!
//! The `sock_diag` netlink subsystem provides a mechanism for obtaining
//! information about sockets of various address families from the
//! kernel.  This subsystem can be used to obtain information about
//! individual sockets or request a list of sockets.
//!
//! In the request, the caller can specify additional information it
//! would like to obtain about the socket, for example, memory
//! information or information specific to the address family.
//!
//! When requesting a list of sockets, the caller can specify filters
//! that would be applied by the kernel to select a subset of sockets to
//! report.  For now, there is only the ability to filter sockets by
//! state (connected, listening, and so on.)
//!
//! Note that sock_diag reports only those sockets that have a name; that
//! is, either sockets bound explicitly with `bind(2)` or sockets that were
//! automatically bound to an address (e.g., by `connect(2)`).  This is the
//! same set of sockets that is available via `/proc/net/unix`,
//! `/proc/net/tcp`, `/proc/net/udp`, and so on.
//!
pub mod inet_diag;
pub mod sock_diag;
pub mod unix_diag;

mod buffer;
mod bytecode;
mod message;

pub use self::inet_diag::{
    extension as Extension, inet_diag_meminfo as MemInfo, tcp_info as TcpInfo,
    tcp_state as TcpState,
};
pub use self::sock_diag::sk_meminfo as SkMemInfo;
pub use self::unix_diag::{attribute as Attribute, unix_state as UnixState};

pub use self::buffer::{
    Extensions, InetDiagAttr, Show, Shutdown, TcpStates, Timer, UnixDiagAttr, UnixStates,
};
pub use self::message::*;
