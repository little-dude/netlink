use std::ffi::CStr;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr::NonNull;
use std::time::Duration;

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use try_from::TryFrom;

use crate::sock_diag::{
    buffer::{array_of, RtaIterator, SDIAG_FAMILY, SDIAG_PROTOCOL},
    inet::raw::{INET_DIAG_MAX, TCP_STATE_MAX},
    Extension,
    Extension::*,
    MemInfo, Shutdown, SkMemInfo, TcpInfo, TcpState,
    TcpState::*,
};
use crate::{DecodeError, Field, Parseable, ParseableParametrized, Rest};

const IDIAG_SPORT: Field = 0..2;
const IDIAG_DPORT: Field = 2..4;
const IDIAG_SRC: Field = array_of::<u32>(4, 4);
const IDIAG_DST: Field = array_of::<u32>(20, 4);
const IDIAG_IF: Field = 36..40;
const IDIAG_COOKIE: Field = array_of::<u32>(40, 2);
const IDIAG_ID_SIZE: usize = IDIAG_COOKIE.end;

const INET_DIAG_NOCOOKIE: u64 = !0;

const IDIAG_REQ_EXT: usize = 2;
const IDIAG_REQ_STATES: Field = 4..8;
const IDIAG_REQ_ID: Field = 8..56;
const IDIAG_REQ_SIZE: usize = IDIAG_REQ_ID.end;
const IDIAG_REQ_ATTRIBUTES: Rest = IDIAG_REQ_SIZE..;

const IDIAG_MSG_FAMILY: usize = 0;
const IDIAG_MSG_STATE: usize = 1;
const IDIAG_MSG_TIMER: usize = 2;
const IDIAG_MSG_RETRANS: usize = 3;
const IDIAG_MSG_ID: Field = 4..52;
const IDIAG_MSG_EXPIRES: Field = 52..56;
const IDIAG_MSG_RQUEUE: Field = 56..60;
const IDIAG_MSG_WQUEUE: Field = 60..64;
const IDIAG_MSG_UID: Field = 64..68;
const IDIAG_MSG_INODE: Field = 68..72;
const IDIAG_MSG_SIZE: usize = IDIAG_MSG_INODE.end;
const IDIAG_MSG_ATTRIBUTES: Rest = IDIAG_MSG_SIZE..;

impl TryFrom<u16> for Extension {
    type Err = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Err> {
        if value <= INET_DIAG_MAX {
            Ok(unsafe { mem::transmute(value) })
        } else {
            Err(format!("unknown extension: {}", value).into())
        }
    }
}

bitflags! {
    /// This is a set of flags defining what kind of extended information to report.
    pub struct Extensions: u8 {
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

impl Default for Extensions {
    fn default() -> Self {
        Extensions::empty()
    }
}

/// The type of timer that is currently active for the TCP socket.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Timer {
    /// a retransmit timer
    Retransmit(u8),
    /// a keep-alive timer
    KeepAlive(u8),
    /// a TIME_WAIT timer
    TimeWait,
    /// a zero window probe timer
    Probe(u8),
}

impl TryFrom<u8> for TcpState {
    type Err = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Err> {
        if 0 < value && value <= TCP_STATE_MAX {
            Ok(unsafe { mem::transmute(value) })
        } else {
            Err(format!("contains unknown state: {}", value).into())
        }
    }
}

bitflags! {
    /// This is a bit mask that defines a filter of TCP socket states.
    pub struct TcpStates: u32 {
        /// (both server and client) represents an open connection, data received can be delivered to the user.
        /// The normal state for the data transfer phase of the connection.
        const ESTABLISHED = 1 << TCP_ESTABLISHED as u8;
        /// (client) represents waiting for a matching connection request after having sent a connection request.
        const SYN_SENT = 1 <<TCP_SYN_SENT as u8;
        /// (server) represents waiting for a confirming connection request acknowledgment
        /// after having both received and sent a connection request.
        const SYN_RECV = 1 << TCP_SYN_RECV as u8;
        /// (both server and client) represents waiting for a connection termination request from the remote TCP,
        /// or an acknowledgment of the connection termination request previously sent.
        const FIN_WAIT1 = 1 << TCP_FIN_WAIT1 as u8;
        /// (both server and client) represents waiting for a connection termination request from the remote TCP.
        const FIN_WAIT2 = 1 << TCP_FIN_WAIT2 as u8;
        /// (either server or client) represents waiting for enough time to pass to be sure
        /// the remote TCP received the acknowledgment of its connection termination request.
        const TIME_WAIT = 1 << TCP_TIME_WAIT as u8;
        /// (both server and client) represents no connection state at all.
        const CLOSE = 1 << TCP_CLOSE as u8;
        /// (both server and client) represents waiting for a connection termination request from the local user.
        const CLOSE_WAIT = 1 << TCP_CLOSE_WAIT as u8;
        /// (both server and client) represents waiting for an acknowledgment of the connection termination request
        /// previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).
        const LAST_ACK = 1 << TCP_LAST_ACK as u8;
        /// (server) represents waiting for a connection request from any remote TCP and port.
        const LISTEN = 1 << TCP_LISTEN as u8;
        /// (both server and client) represents waiting for a connection termination request acknowledgment from the remote TCP.
        const CLOSING = 1 << TCP_CLOSING as u8;
    }
}

impl Default for TcpStates {
    fn default() -> Self {
        TcpStates::all()
    }
}

impl<T: AsRef<[u8]>> Parseable<TcpInfo> for T {
    fn parse(&self) -> Result<TcpInfo, DecodeError> {
        let data = self.as_ref();

        if data.len() >= mem::size_of::<TcpInfo>() {
            Ok(unsafe {
                NonNull::new_unchecked(data.as_ptr() as *mut u8)
                    .cast::<TcpInfo>()
                    .as_ptr()
                    .read()
            })
        } else {
            Err(format!(
                "buffer size is {}, whereas a buffer is at least {} long",
                data.len(),
                mem::size_of::<TcpInfo>()
            )
            .into())
        }
    }
}

impl<T: AsRef<[u8]>> Parseable<MemInfo> for T {
    fn parse(&self) -> Result<MemInfo, DecodeError> {
        let data = self.as_ref();

        if data.len() >= mem::size_of::<MemInfo>() {
            Ok(unsafe {
                NonNull::new_unchecked(data.as_ptr() as *mut u8)
                    .cast::<MemInfo>()
                    .as_ptr()
                    .read()
            })
        } else {
            Err(format!(
                "buffer size is {}, whereas a buffer is at least {} long",
                data.len(),
                mem::size_of::<MemInfo>()
            )
            .into())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SocketIdBuffer<T> {
    buffer: T,
}

impl<T> SocketIdBuffer<T> {
    pub fn new(buffer: T) -> SocketIdBuffer<T> {
        SocketIdBuffer { buffer }
    }

    pub const fn len() -> usize {
        IDIAG_ID_SIZE
    }
}

impl<T: AsRef<[u8]>> SocketIdBuffer<T> {
    pub fn sport(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[IDIAG_SPORT])
    }

    pub fn dport(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[IDIAG_DPORT])
    }

    pub fn src_ipv4(&self) -> Ipv4Addr {
        let data = self.buffer.as_ref();
        Ipv4Addr::from(NetworkEndian::read_u32(&data[IDIAG_SRC]))
    }

    pub fn src_ipv6(&self) -> Ipv6Addr {
        let data = self.buffer.as_ref();
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[IDIAG_SRC]);
        Ipv6Addr::from(addr)
    }

    pub fn dst_ipv4(&self) -> Ipv4Addr {
        let data = self.buffer.as_ref();
        Ipv4Addr::from(NetworkEndian::read_u32(&data[IDIAG_DST]))
    }

    pub fn dst_ipv6(&self) -> Ipv6Addr {
        let data = self.buffer.as_ref();
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[IDIAG_DST]);
        Ipv6Addr::from(addr)
    }

    pub fn interface(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[IDIAG_IF])
    }

    pub fn cookie(&self) -> Option<u64> {
        let data = self.buffer.as_ref();
        let mut cookie = [0u32; 2];
        NativeEndian::read_u32_into(&data[IDIAG_COOKIE], &mut cookie);
        let cookie = u64::from(cookie[0]) + (u64::from(cookie[1]) << 32);

        if cookie == INET_DIAG_NOCOOKIE {
            None
        } else {
            Some(cookie)
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> SocketIdBuffer<T> {
    pub fn set_sport(&mut self, port: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[IDIAG_SPORT], port)
    }

    pub fn set_dport(&mut self, port: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[IDIAG_DPORT], port)
    }

    pub fn set_src_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(addr) => {
                self.set_src_ipv4(addr.ip());
                self.set_sport(addr.port());
            }
            SocketAddr::V6(addr) => {
                self.set_src_ipv6(addr.ip());
                self.set_sport(addr.port());
            }
        }
    }

    pub fn set_src_ipv4(&mut self, addr: &Ipv4Addr) {
        let data = self.buffer.as_mut();
        data[IDIAG_SRC].copy_from_slice(&addr.octets());
    }

    pub fn set_src_ipv6(&mut self, addr: &Ipv6Addr) {
        let data = self.buffer.as_mut();
        data[IDIAG_SRC].copy_from_slice(&addr.octets());
    }

    pub fn set_dst_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(addr) => {
                self.set_dst_ipv4(addr.ip());
                self.set_dport(addr.port());
            }
            SocketAddr::V6(addr) => {
                self.set_dst_ipv6(addr.ip());
                self.set_dport(addr.port());
            }
        }
    }

    pub fn set_dst_ipv4(&mut self, addr: &Ipv4Addr) {
        let data = self.buffer.as_mut();
        data[IDIAG_DST].copy_from_slice(&addr.octets());
    }

    pub fn set_dst_ipv6(&mut self, addr: &Ipv6Addr) {
        let data = self.buffer.as_mut();
        data[IDIAG_DST].copy_from_slice(&addr.octets());
    }

    pub fn set_interface(&mut self, intf: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IDIAG_IF], intf)
    }

    pub fn set_cookie(&mut self, cookie: Option<u64>) {
        let data = self.buffer.as_mut();
        let cookie = cookie.unwrap_or(INET_DIAG_NOCOOKIE);
        let cookie = [cookie as u32, (cookie >> 32) as u32];
        NativeEndian::write_u32_into(&cookie[..], &mut data[IDIAG_COOKIE]);
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
        IDIAG_REQ_SIZE
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
    pub fn extensions(&self) -> Extensions {
        let data = self.buffer.as_ref();
        Extensions::from_bits_truncate(data[IDIAG_REQ_EXT])
    }
    pub fn states(&self) -> TcpStates {
        let data = self.buffer.as_ref();
        TcpStates::from_bits_truncate(NativeEndian::read_u32(&data[IDIAG_REQ_STATES]))
    }
    pub fn id(&self) -> SocketIdBuffer<&[u8]> {
        let data = self.buffer.as_ref();

        SocketIdBuffer::new(&data[IDIAG_REQ_ID])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RequestBuffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buffer.as_mut();
        data[SDIAG_FAMILY] = family
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        let data = self.buffer.as_mut();
        data[SDIAG_PROTOCOL] = protocol
    }

    pub fn set_extensions(&mut self, ext: Extensions) {
        let data = self.buffer.as_mut();
        data[IDIAG_REQ_EXT] = ext.bits()
    }

    pub fn set_states(&mut self, states: TcpStates) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IDIAG_REQ_STATES], states.bits())
    }

    pub fn id_mut(&mut self) -> SocketIdBuffer<&mut [u8]> {
        let data = self.buffer.as_mut();
        SocketIdBuffer::new(&mut data[IDIAG_REQ_ID])
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
        IDIAG_MSG_SIZE
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
        if len < IDIAG_MSG_SIZE {
            Err(format!(
                "buffer size is {}, whereas a rule buffer is at least {} long",
                len, IDIAG_MSG_SIZE
            )
            .into())
        } else {
            Ok(())
        }
    }

    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[IDIAG_MSG_FAMILY]
    }

    pub fn state(&self) -> Result<TcpState, DecodeError> {
        let data = self.buffer.as_ref();
        TcpState::try_from(data[IDIAG_MSG_STATE])
    }

    pub fn timer(&self) -> Option<Timer> {
        let data = self.buffer.as_ref();
        match data[IDIAG_MSG_TIMER] {
            1 => Some(Timer::Retransmit(data[IDIAG_MSG_RETRANS])),
            2 => Some(Timer::KeepAlive(data[IDIAG_MSG_RETRANS])),
            3 => Some(Timer::TimeWait),
            4 => Some(Timer::Probe(data[IDIAG_MSG_RETRANS])),
            _ => None,
        }
    }

    pub fn id(&self) -> SocketIdBuffer<&[u8]> {
        let data = self.buffer.as_ref();
        SocketIdBuffer::new(&data[IDIAG_MSG_ID])
    }

    pub fn expires(&self) -> Option<Duration> {
        let data = self.buffer.as_ref();
        let expires = NativeEndian::read_u32(&data[IDIAG_MSG_EXPIRES]);
        if expires == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(expires)))
        }
    }

    pub fn rqueue(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[IDIAG_MSG_RQUEUE])
    }

    pub fn wqueue(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[IDIAG_MSG_WQUEUE])
    }

    pub fn uid(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[IDIAG_MSG_UID])
    }

    pub fn inode(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[IDIAG_MSG_INODE])
    }

    pub fn attrs(&self) -> RtaIterator<&[u8]> {
        let data = self.buffer.as_ref();
        RtaIterator::new(&data[IDIAG_MSG_ATTRIBUTES])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ResponseBuffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buffer.as_mut();
        data[IDIAG_MSG_FAMILY] = family
    }

    pub fn set_state(&mut self, state: TcpState) {
        let data = self.buffer.as_mut();
        data[IDIAG_MSG_STATE] = state as u8
    }

    pub fn set_timer(&mut self, timer: u8) {
        let data = self.buffer.as_mut();
        data[IDIAG_MSG_TIMER] = timer
    }

    pub fn set_retrans(&mut self, retrans: u8) {
        let data = self.buffer.as_mut();
        data[IDIAG_MSG_RETRANS] = retrans
    }

    pub fn id_mut(&mut self) -> SocketIdBuffer<&mut [u8]> {
        let data = self.buffer.as_mut();
        SocketIdBuffer::new(&mut data[IDIAG_MSG_ID])
    }

    pub fn set_expires(&mut self, expires: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IDIAG_MSG_EXPIRES], expires)
    }

    pub fn set_rqueue(&mut self, rqueue: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IDIAG_MSG_RQUEUE], rqueue)
    }

    pub fn set_wqueue(&mut self, wqueue: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IDIAG_MSG_WQUEUE], wqueue)
    }

    pub fn set_uid(&mut self, uid: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IDIAG_MSG_UID], uid)
    }

    pub fn set_inode(&mut self, inode: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[IDIAG_MSG_INODE], inode)
    }
}

/// The socket extended information
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Attr {
    /// the memory information of the socket.
    MemInfo(MemInfo),
    /// the TCP information
    Info(Box<TcpInfo>),
    /// the congestion control algorithm used
    Conf(String),
    /// the TOS of the socket.
    Tos(u8),
    /// the TClass of the socket.
    TClass(u8),
    /// socket memory information
    SkMemInfo(SkMemInfo),
    /// shutdown states
    Shutdown(Shutdown),
    /// The protocol
    Protocol(u8),
    /// The socket is IPv6 only
    SkV6Only(bool),
    /// The mark of the socket.
    Mark(u32),
    /// The class ID of the socket.
    ClassId(u32),
    /// other attribute
    Other(Extension, Vec<u8>),
}

impl<T: AsRef<[u8]>> ParseableParametrized<Attr, Extension> for T {
    fn parse_with_param(&self, ty: Extension) -> Result<Attr, DecodeError> {
        use Extension::*;

        let payload = self.as_ref();

        Ok(match ty {
            INET_DIAG_MEMINFO if payload.len() >= mem::size_of::<MemInfo>() => {
                Attr::MemInfo(payload.parse()?)
            }
            INET_DIAG_INFO if payload.len() >= mem::size_of::<TcpInfo>() => {
                Attr::Info(Box::new(payload.parse()?))
            }
            INET_DIAG_CONG => Attr::Conf(unsafe {
                CStr::from_bytes_with_nul_unchecked(payload)
                    .to_string_lossy()
                    .into_owned()
            }),
            INET_DIAG_TOS if !payload.is_empty() => Attr::Tos(payload[0]),
            INET_DIAG_TCLASS if !payload.is_empty() => Attr::TClass(payload[0]),
            INET_DIAG_SKMEMINFO if payload.len() > mem::size_of::<SkMemInfo>() => {
                Attr::SkMemInfo(payload.parse()?)
            }
            INET_DIAG_SHUTDOWN if !payload.is_empty() => {
                Attr::Shutdown(Shutdown::from_bits_truncate(payload[0]))
            }
            INET_DIAG_PROTOCOL if !payload.is_empty() => Attr::Protocol(payload[0]),
            INET_DIAG_SKV6ONLY if !payload.is_empty() => Attr::SkV6Only(payload[0] != 0),
            INET_DIAG_MARK if payload.len() >= 4 => Attr::Mark(NativeEndian::read_u32(payload)),
            INET_DIAG_CLASS_ID if payload.len() >= 4 => {
                Attr::ClassId(NativeEndian::read_u32(payload))
            }
            _ => Attr::Other(ty, payload.to_vec()),
        })
    }
}
