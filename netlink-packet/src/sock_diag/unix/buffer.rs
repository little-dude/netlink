use std::ffi::CStr;
use std::mem;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;
use try_from::TryFrom;

use crate::sock_diag::{
    buffer::{array_of, RtaIterator, SDIAG_FAMILY, SDIAG_PROTOCOL},
    inet::INET_DIAG_NOCOOKIE,
    unix::raw::{show::*, unix_diag_rqlen, unix_diag_vfs, UNIX_DIAG_MAX, UNIX_STATE_MAX},
    Attribute, Shutdown, SkMemInfo,
    TcpState::*,
    UnixState,
};
use crate::{DecodeError, Field, Parseable, ParseableParametrized, Rest};

const UDIAG_REQ_STATES: Field = 4..8;
const UDIAG_REQ_INO: Field = 8..12;
const UDIAG_REQ_SHOW: Field = 12..16;
const UDIAG_REQ_COOKIE: Field = array_of::<u32>(16, 2);
const UDIAG_REQ_SIZE: usize = UDIAG_REQ_COOKIE.end;

const UDIAG_MSG_FAMILY: usize = 0;
const UDIAG_MSG_TYPE: usize = 1;
const UDIAG_MSG_STATE: usize = 2;
const UDIAG_MSG_INO: Field = 4..8;
const UDIAG_MSG_COOKIE: Field = array_of::<u32>(8, 2);
const UDIAG_MSG_SIZE: usize = UDIAG_MSG_COOKIE.end;
const UDIAG_MSG_ATTRIBUTES: Rest = UDIAG_MSG_SIZE..;

impl TryFrom<u8> for UnixState {
    type Err = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Err> {
        if value <= UNIX_STATE_MAX {
            Ok(unsafe { mem::transmute(value) })
        } else {
            Err(format!("unknown UNIX state: {}", value).into())
        }
    }
}

bitflags! {
    /// This is a bit mask that defines a filter of UNIX sockets states.
    pub struct UnixStates: u32 {
        const ESTABLISHED = 1 << TCP_ESTABLISHED as u8;
        const LISTEN = 1 << TCP_LISTEN as u8;
    }
}

impl Default for UnixStates {
    fn default() -> Self {
        UnixStates::all()
    }
}

bitflags! {
    ///  This is a set of flags defining what kind of information to report.
    pub struct Show: u32 {
        /// show name (not path)
        const NAME = UDIAG_SHOW_NAME as u32;
        /// show VFS inode info
        const VFS = UDIAG_SHOW_VFS as u32;
        /// show peer socket info
        const PEER = UDIAG_SHOW_PEER as u32;
        /// show pending connections
        const ICONS = UDIAG_SHOW_ICONS as u32;
        /// show skb receive queue len
        const RQLEN = UDIAG_SHOW_RQLEN as u32;
        /// show memory info of a socket
        const MEMINFO = UDIAG_SHOW_MEMINFO as u32;
    }
}

impl TryFrom<u16> for Attribute {
    type Err = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Err> {
        if value <= UNIX_DIAG_MAX {
            Ok(unsafe { mem::transmute(value) })
        } else {
            Err(format!("unknown UNIX attribute: {}", value).into())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestBuffer<T> {
    buffer: T,
}

impl<T> RequestBuffer<T> {
    pub fn new(buffer: T) -> RequestBuffer<T> {
        RequestBuffer { buffer }
    }

    pub const fn len() -> usize {
        UDIAG_REQ_SIZE
    }
}

impl<T: AsRef<[u8]>> RequestBuffer<T> {
    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SDIAG_FAMILY]
    }
    pub fn protocol(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SDIAG_PROTOCOL]
    }
    pub fn states(&self) -> UnixStates {
        let data = self.buffer.as_ref();
        UnixStates::from_bits_truncate(NativeEndian::read_u32(&data[UDIAG_REQ_STATES]))
    }
    pub fn inode(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[UDIAG_REQ_INO])
    }
    pub fn show(&self) -> Show {
        let data = self.buffer.as_ref();
        Show::from_bits_truncate(NativeEndian::read_u32(&data[UDIAG_REQ_SHOW]))
    }
    pub fn cookie(&self) -> Option<u64> {
        let data = self.buffer.as_ref();
        let mut cookie = [0u32; 2];
        NativeEndian::read_u32_into(&data[UDIAG_REQ_COOKIE], &mut cookie);
        let cookie = u64::from(cookie[0]) + (u64::from(cookie[1]) << 32);

        if cookie == INET_DIAG_NOCOOKIE {
            None
        } else {
            Some(cookie)
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RequestBuffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buffer.as_mut();
        data[SDIAG_FAMILY] = family;
    }
    pub fn set_protocol(&mut self, protocol: u8) {
        let data = self.buffer.as_mut();
        data[SDIAG_PROTOCOL] = protocol
    }
    pub fn set_states(&mut self, states: UnixStates) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[UDIAG_REQ_STATES], states.bits())
    }
    pub fn set_inode(&mut self, inode: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[UDIAG_REQ_INO], inode)
    }
    pub fn set_show(&mut self, show: Show) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[UDIAG_REQ_SHOW], show.bits())
    }
    pub fn set_cookie(&mut self, cookie: Option<u64>) {
        let data = self.buffer.as_mut();
        let cookie = cookie.unwrap_or(INET_DIAG_NOCOOKIE);
        let cookie = [cookie as u32, (cookie >> 32) as u32];
        NativeEndian::write_u32_into(&cookie[..], &mut data[UDIAG_REQ_COOKIE]);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ResponseBuffer<T> {
    buffer: T,
}

impl<T> ResponseBuffer<T> {
    pub fn new(buffer: T) -> ResponseBuffer<T> {
        ResponseBuffer { buffer }
    }

    pub const fn len() -> usize {
        UDIAG_MSG_SIZE
    }
}

impl<T: AsRef<[u8]>> ResponseBuffer<T> {
    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    fn check_len(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < UDIAG_MSG_SIZE {
            Err(format!(
                "buffer size is {}, whereas a rule buffer is at least {} long",
                len, UDIAG_MSG_SIZE
            )
            .into())
        } else {
            Ok(())
        }
    }

    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[UDIAG_MSG_FAMILY]
    }
    pub fn ty(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[UDIAG_MSG_TYPE]
    }
    pub fn state(&self) -> Result<UnixState, DecodeError> {
        let data = self.buffer.as_ref();
        UnixState::try_from(data[UDIAG_MSG_STATE])
    }
    pub fn inode(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[UDIAG_MSG_INO])
    }
    pub fn cookie(&self) -> Option<u64> {
        let data = self.buffer.as_ref();
        let mut cookie = [0u32; 2];
        NativeEndian::read_u32_into(&data[UDIAG_MSG_COOKIE], &mut cookie);
        let cookie = u64::from(cookie[0]) + (u64::from(cookie[1]) << 32);

        if cookie == INET_DIAG_NOCOOKIE {
            None
        } else {
            Some(cookie)
        }
    }
    pub fn attrs(&self) -> RtaIterator<&[u8]> {
        let data = self.buffer.as_ref();
        RtaIterator::new(&data[UDIAG_MSG_ATTRIBUTES])
    }
}

/// UNIX socket information
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Attr {
    /// name (not path)
    Name(String),
    /// VFS inode info
    Vfs(unix_diag_vfs),
    /// peer socket info
    Peer(u32),
    /// pending connections
    Icons(Vec<u32>),
    /// skb receive queue len
    RecvQueueLen(unix_diag_rqlen),
    /// memory info of a socket
    MemInfo(SkMemInfo),
    /// shutdown states
    Shutdown(Shutdown),
    /// other attribute
    Other(Attribute, Vec<u8>),
}

impl<T: AsRef<[u8]>> ParseableParametrized<Attr, Attribute> for T {
    fn parse_with_param(&self, ty: Attribute) -> Result<Attr, DecodeError> {
        use Attribute::*;

        let payload = self.as_ref();

        Ok(match ty {
            UNIX_DIAG_NAME if !payload.is_empty() => Attr::Name(
                CStr::from_bytes_with_nul(payload)
                    .context("invalid name")?
                    .to_str()
                    .context("invalid name")?
                    .to_owned(),
            ),
            UNIX_DIAG_VFS if payload.len() >= mem::size_of::<[u32; 2]>() => {
                Attr::Vfs(unix_diag_vfs {
                    udiag_vfs_ino: NativeEndian::read_u32(&payload[0..4]),
                    udiag_vfs_dev: NativeEndian::read_u32(&payload[4..8]),
                })
            }
            UNIX_DIAG_PEER if payload.len() >= mem::size_of::<u32>() => {
                Attr::Peer(NativeEndian::read_u32(payload))
            }
            UNIX_DIAG_ICONS => {
                let mut icons = vec![0; payload.len() / 4];
                NativeEndian::read_u32_into(&payload[..icons.len() * 4], icons.as_mut_slice());
                Attr::Icons(icons)
            }
            UNIX_DIAG_RQLEN if payload.len() >= mem::size_of::<[u32; 2]>() => {
                Attr::RecvQueueLen(unix_diag_rqlen {
                    udiag_rqueue: NativeEndian::read_u32(&payload[0..4]),
                    udiag_wqueue: NativeEndian::read_u32(&payload[4..8]),
                })
            }
            UNIX_DIAG_MEMINFO if payload.len() > mem::size_of::<SkMemInfo>() => {
                Attr::MemInfo(payload.parse()?)
            }
            UNIX_DIAG_SHUTDOWN if !payload.is_empty() => {
                Attr::Shutdown(Shutdown::from_bits_truncate(payload[0]))
            }
            _ => Attr::Other(ty, payload.to_vec()),
        })
    }
}
