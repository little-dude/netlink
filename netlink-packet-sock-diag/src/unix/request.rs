use std::convert::TryFrom;

use crate::{
    constants::*,
    traits::{Emitable, Parseable},
    DecodeError,
};

pub const UNIX_REQUEST_LEN: usize = 24;

buffer!(UnixRequestBuffer(UNIX_REQUEST_LEN) {
    // The address family; it should be set to `AF_UNIX`
    family: (u8, 0),
    // This field should be set to `0`
    protocol: (u8, 1),
    // This field should be set to `0`
    pad: (u16, 2..4),
    // This is a bit mask that defines a filter of sockets
    // states. Only those sockets whose states are in this mask will
    // be reported. Ignored when querying for an individual
    // socket. Supported values are:
    //
    // ```no_rust
    // 1 << UNIX_ESTABLISHED
    // 1 << UNIX_LISTEN
    // ```
    state_flags: (u32, 4..8),
    // This is an inode number when querying for an individual
    // socket. Ignored when querying for a list of sockets.
    inode: (u32, 8..12),
    // This is a set of flags defining what kind of information to
    // report. Supported values are the `UDIAG_SHOW_*` constants.
    show_flags: (u32, 12..16),
    // This is an array of opaque identifiers that could be used
    // along with udiag_ino to specify an individual socket. It is
    // ignored when querying for a list of sockets, as well as when
    // all its elements are set to `0xff`.
    cookie: (slice, 16..UNIX_REQUEST_LEN),
});

/// The request for UNIX domain sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnixRequest {
    /// This is a bit mask that defines a filter of sockets states.
    ///
    /// Only those sockets whose states are in this mask will be reported.
    /// Ignored when querying for an individual socket.
    pub state_flags: StateFlags,
    /// This is an inode number when querying for an individual socket.
    ///
    /// Ignored when querying for a list of sockets.
    pub inode: u32,
    /// This is a set of flags defining what kind of information to report.
    ///
    /// Each requested kind of information is reported back as a netlink attribute
    pub show_flags: ShowFlags,
    /// This is an opaque identifiers that could be used to specify an individual socket.
    pub cookie: [u8; 8],
}

bitflags! {
    /// Bitmask that defines a filter of UNIX socket states
    pub struct StateFlags: u32 {
        const ESTABLISHED = 1 << TCP_ESTABLISHED;
        const LISTEN = 1 << TCP_LISTEN;
    }
}

bitflags! {
    /// Bitmask that defines what kind of information to
    /// report. Supported values are the `UDIAG_SHOW_*` constants.
    pub struct ShowFlags: u32 {
        const NAME = UDIAG_SHOW_NAME;
        const VFS = UDIAG_SHOW_VFS;
        const PEER = UDIAG_SHOW_PEER;
        const ICONS = UDIAG_SHOW_ICONS;
        const RQLEN = UDIAG_SHOW_RQLEN;
        const MEMINFO = UDIAG_SHOW_MEMINFO;
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<UnixRequestBuffer<&'a T>> for UnixRequest {
    fn parse(buf: &UnixRequestBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            state_flags: StateFlags::from_bits_truncate(buf.state_flags()),
            inode: buf.inode(),
            show_flags: ShowFlags::from_bits_truncate(buf.show_flags()),
            // Unwrapping is safe because UnixRequestBuffer::cookie()
            // returns a slice of exactly 8 bytes.
            cookie: TryFrom::try_from(buf.cookie()).unwrap(),
        })
    }
}

impl Emitable for UnixRequest {
    fn buffer_len(&self) -> usize {
        UNIX_REQUEST_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buffer = UnixRequestBuffer::new(buf);
        buffer.set_family(0);
        buffer.set_protocol(0);
        buffer.set_state_flags(self.state_flags.bits());
        buffer.set_inode(self.inode);
        buffer.set_pad(0);
        buffer.set_show_flags(self.show_flags.bits());
        buffer.cookie_mut().copy_from_slice(&self.cookie[..]);
    }
}
