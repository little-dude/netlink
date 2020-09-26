use anyhow::Context;

use crate::{
    constants::*,
    inet::{SocketId, SocketIdBuffer},
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

pub const REQUEST_LEN: usize = 56;

buffer!(InetRequestBuffer(REQUEST_LEN) {
    family: (u8, 0),
    protocol: (u8, 1),
    extensions: (u8, 2),
    pad: (u8, 3),
    states: (u32, 4..8),
    socket_id: (slice, 8..56),
});

/// A request for Ipv4 and Ipv6 sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InetRequest {
    /// The address family, either `AF_INET` or `AF_INET6`
    pub family: u8,
    /// The IP protocol. This field should be set to one of the
    /// `IPPROTO_*` constants
    pub protocol: u8,
    /// Set of flags defining what kind of extended information to
    /// report. Each requested kind of information is reported back as
    /// a netlink attribute.
    pub extensions: ExtensionFlags,
    /// Bitmask that defines a filter of TCP socket states
    pub states: StateFlags,
    /// A socket ID object that is used in dump requests, in queries
    /// about individual sockets, and is reported back in each
    /// response.
    ///
    /// Unlike UNIX domain sockets, IPv4 and IPv6 sockets are
    /// identified using addresses and ports.
    pub socket_id: SocketId,
}

bitflags! {
    /// Bitmask that defines a filter of TCP socket states
    pub struct StateFlags: u32 {
        /// (server and client) represents an open connection,
        /// data received can be delivered to the user. The normal
        /// state for the data transfer phase of the connection.
        const ESTABLISHED = 1 << TCP_ESTABLISHED ;
        /// (client) represents waiting for a matching connection
        /// request after having sent a connection request.
        const SYN_SENT = 1 <<TCP_SYN_SENT ;
        /// (server) represents waiting for a confirming connection
        /// request acknowledgment after having both received and sent
        /// a connection request.
        const SYN_RECV = 1 << TCP_SYN_RECV ;
        /// (both server and client) represents waiting for a
        /// connection termination request from the remote TCP, or an
        /// acknowledgment of the connection termination request
        /// previously sent.
        const FIN_WAIT1 = 1 << TCP_FIN_WAIT1 ;
        /// (both server and client) represents waiting for a
        /// connection termination request from the remote TCP.
        const FIN_WAIT2 = 1 << TCP_FIN_WAIT2 ;
        /// (either server or client) represents waiting for enough
        /// time to pass to be sure the remote TCP received the
        /// acknowledgment of its connection termination request.
        const TIME_WAIT = 1 << TCP_TIME_WAIT ;
        /// (both server and client) represents no connection state at
        /// all.
        const CLOSE = 1 << TCP_CLOSE ;
        /// (both server and client) represents waiting for a
        /// connection termination request from the local user.
        const CLOSE_WAIT = 1 << TCP_CLOSE_WAIT ;
        /// (both server and client) represents waiting for an
        /// acknowledgment of the connection termination request
        /// previously sent to the remote TCP (which includes an
        /// acknowledgment of its connection termination request).
        const LAST_ACK = 1 << TCP_LAST_ACK ;
        /// (server) represents waiting for a connection request from
        /// any remote TCP and port.
        const LISTEN = 1 << TCP_LISTEN ;
        /// (both server and client) represents waiting for a
        /// connection termination request acknowledgment from the
        /// remote TCP.
        const CLOSING = 1 << TCP_CLOSING ;
    }
}

bitflags! {
    /// This is a set of flags defining what kind of extended
    /// information to report.
    pub struct ExtensionFlags: u8 {
        const MEMINFO = 1 << (INET_DIAG_MEMINFO as u16 - 1);
        const INFO = 1 << (INET_DIAG_INFO as u16 - 1);
        const VEGASINFO = 1 << (INET_DIAG_VEGASINFO as u16 - 1);
        const CONF = 1 << (INET_DIAG_CONG as u16 - 1);
        const TOS = 1 << (INET_DIAG_TOS as u16 - 1);
        const TCLASS = 1 << (INET_DIAG_TCLASS as u16 - 1);
        const SKMEMINFO = 1 << (INET_DIAG_SKMEMINFO as u16 - 1);
        const SHUTDOWN = 1 << (INET_DIAG_SHUTDOWN as u16 - 1);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<InetRequestBuffer<&'a T>> for InetRequest {
    fn parse(buf: &InetRequestBuffer<&'a T>) -> Result<Self, DecodeError> {
        let err = "invalid socket_id value";
        let socket_id = SocketId::parse_with_param(
            &SocketIdBuffer::new_checked(&buf.socket_id()).context(err)?,
            buf.family(),
        )
        .context(err)?;

        Ok(Self {
            family: buf.family(),
            protocol: buf.protocol(),
            extensions: ExtensionFlags::from_bits_truncate(buf.extensions()),
            states: StateFlags::from_bits_truncate(buf.states()),
            socket_id,
        })
    }
}

impl Emitable for InetRequest {
    fn buffer_len(&self) -> usize {
        REQUEST_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = InetRequestBuffer::new(buf);
        buf.set_family(self.family);
        buf.set_protocol(self.protocol);
        buf.set_extensions(self.extensions.bits());
        buf.set_pad(0);
        buf.set_states(self.states.bits());
        self.socket_id.emit(buf.socket_id_mut())
    }
}
