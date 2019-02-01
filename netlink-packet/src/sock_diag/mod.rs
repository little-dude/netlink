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
pub mod inet;
pub mod sock;
pub mod unix;

mod buffer;
mod message;

pub use self::inet::{
    inet, inet6, Attr as InetDiagAttr, Extension, Extensions, MemInfo, Request as InetDiagRequest,
    Response as InetDiagResponse, TcpInfo, TcpState, TcpStates, Timer,
};
pub use self::sock::SkMemInfo;
pub use self::unix::{
    unix, Attr as UnixDiagAttr, Attribute, Request as UnixDiagRequest,
    Response as UnixDiagResponse, Show, UnixState, UnixStates,
};

pub use self::buffer::Shutdown;
pub use self::message::Message as SockDiagMessage;
