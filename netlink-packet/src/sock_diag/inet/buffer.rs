use std::ffi::CStr;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use failure::ResultExt;
use try_from::TryFrom;

use crate::sock_diag::{
    buffer::{array_of, CStruct, RtaIterator, REQ_FAMILY, REQ_PROTOCOL},
    Extension,
    Extension::*,
    MemInfo, SctpState, Shutdown, SkMemInfo, TcpInfo, TcpState,
    TcpState::*,
};
use crate::{DecodeError, Field, Parseable, ParseableParametrized, Rest};

const ID_SPORT: Field = 0..2;
const ID_DPORT: Field = 2..4;
const ID_SRC: Field = array_of::<u32>(4, 4);
const ID_DST: Field = array_of::<u32>(20, 4);
const ID_IF: Field = 36..40;
const ID_COOKIE: Field = array_of::<u32>(40, 2);
const ID_SIZE: usize = ID_COOKIE.end;

const INET_DIAG_NOCOOKIE: u64 = !0;

const REQ_EXT: usize = 2;
const REQ_STATES: Field = 4..8;
const REQ_ID: Field = 8..56;
const REQ_SIZE: usize = REQ_ID.end;
const REQ_ATTRIBUTES: Rest = REQ_SIZE..;

const MSG_FAMILY: usize = 0;
const MSG_STATE: usize = 1;
const MSG_TIMER: usize = 2;
const MSG_RETRANS: usize = 3;
const MSG_ID: Field = 4..52;
const MSG_EXPIRES: Field = 52..56;
const MSG_RQUEUE: Field = 56..60;
const MSG_WQUEUE: Field = 60..64;
const MSG_UID: Field = 64..68;
const MSG_INODE: Field = 68..72;
const MSG_SIZE: usize = MSG_INODE.end;
const MSG_ATTRIBUTES: Rest = MSG_SIZE..;

impl TryFrom<u16> for Extension {
    type Err = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Err> {
        if value <= Self::max_value() {
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

impl From<Extension> for Extensions {
    fn from(ext: Extension) -> Self {
        Self::from_bits_truncate(1 << (ext as u16 - 1))
    }
}

impl Default for Extensions {
    fn default() -> Self {
        Self::empty()
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
        if Self::min_value() <= value && value <= Self::max_value() {
            Ok(unsafe { mem::transmute(value) })
        } else {
            Err(format!("contains unknown state: {}", value).into())
        }
    }
}

impl TryFrom<u8> for SctpState {
    type Err = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Err> {
        if Self::min_value() <= value && value <= Self::max_value() {
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

impl From<TcpState> for TcpStates {
    fn from(state: TcpState) -> Self {
        Self::from_bits_truncate(1 << (state as u8))
    }
}

impl Default for TcpStates {
    fn default() -> Self {
        Self::empty()
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
        ID_SIZE
    }
}

impl<T: AsRef<[u8]>> SocketIdBuffer<T> {
    pub fn sport(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[ID_SPORT])
    }

    pub fn dport(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[ID_DPORT])
    }

    pub fn src_ipv4(&self) -> Ipv4Addr {
        let data = self.buffer.as_ref();
        Ipv4Addr::from(NetworkEndian::read_u32(&data[ID_SRC]))
    }

    pub fn src_ipv6(&self) -> Ipv6Addr {
        let data = self.buffer.as_ref();
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[ID_SRC]);
        Ipv6Addr::from(addr)
    }

    pub fn dst_ipv4(&self) -> Ipv4Addr {
        let data = self.buffer.as_ref();
        Ipv4Addr::from(NetworkEndian::read_u32(&data[ID_DST]))
    }

    pub fn dst_ipv6(&self) -> Ipv6Addr {
        let data = self.buffer.as_ref();
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[ID_DST]);
        Ipv6Addr::from(addr)
    }

    pub fn interface(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[ID_IF])
    }

    pub fn cookie(&self) -> Option<u64> {
        let data = self.buffer.as_ref();
        let mut cookie = [0u32; 2];
        NativeEndian::read_u32_into(&data[ID_COOKIE], &mut cookie);
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
        NetworkEndian::write_u16(&mut data[ID_SPORT], port)
    }

    pub fn set_dport(&mut self, port: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[ID_DPORT], port)
    }

    pub fn set_src_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(addr) => {
                self.set_src_ipv4(*addr.ip());
                self.set_sport(addr.port());
            }
            SocketAddr::V6(addr) => {
                self.set_src_ipv6(addr.ip());
                self.set_sport(addr.port());
            }
        }
    }

    pub fn set_src_ipv4(&mut self, addr: Ipv4Addr) {
        let data = self.buffer.as_mut();
        data[ID_SRC].copy_from_slice(&addr.octets());
    }

    pub fn set_src_ipv6(&mut self, addr: &Ipv6Addr) {
        let data = self.buffer.as_mut();
        data[ID_SRC].copy_from_slice(&addr.octets());
    }

    pub fn set_dst_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(addr) => {
                self.set_dst_ipv4(*addr.ip());
                self.set_dport(addr.port());
            }
            SocketAddr::V6(addr) => {
                self.set_dst_ipv6(addr.ip());
                self.set_dport(addr.port());
            }
        }
    }

    pub fn set_dst_ipv4(&mut self, addr: Ipv4Addr) {
        let data = self.buffer.as_mut();
        data[ID_DST].copy_from_slice(&addr.octets());
    }

    pub fn set_dst_ipv6(&mut self, addr: &Ipv6Addr) {
        let data = self.buffer.as_mut();
        data[ID_DST].copy_from_slice(&addr.octets());
    }

    pub fn set_interface(&mut self, intf: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[ID_IF], intf)
    }

    pub fn set_cookie(&mut self, cookie: Option<u64>) {
        let data = self.buffer.as_mut();
        let cookie = cookie.unwrap_or(INET_DIAG_NOCOOKIE);
        let cookie = [cookie as u32, (cookie >> 32) as u32];
        NativeEndian::write_u32_into(&cookie[..], &mut data[ID_COOKIE]);
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
        REQ_SIZE
    }
}

impl<T: AsRef<[u8]>> RequestBuffer<T> {
    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[REQ_FAMILY]
    }
    pub fn protocol(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[REQ_PROTOCOL]
    }
    pub fn extensions(&self) -> Extensions {
        let data = self.buffer.as_ref();
        Extensions::from_bits_truncate(data[REQ_EXT])
    }
    pub fn states(&self) -> TcpStates {
        let data = self.buffer.as_ref();
        TcpStates::from_bits_truncate(NativeEndian::read_u32(&data[REQ_STATES]))
    }
    pub fn id(&self) -> SocketIdBuffer<&[u8]> {
        let data = self.buffer.as_ref();

        SocketIdBuffer::new(&data[REQ_ID])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RequestBuffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buffer.as_mut();
        data[REQ_FAMILY] = family
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        let data = self.buffer.as_mut();
        data[REQ_PROTOCOL] = protocol
    }

    pub fn set_extensions(&mut self, ext: Extensions) {
        let data = self.buffer.as_mut();
        data[REQ_EXT] = ext.bits()
    }

    pub fn set_states(&mut self, states: TcpStates) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[REQ_STATES], states.bits())
    }

    pub fn id_mut(&mut self) -> SocketIdBuffer<&mut [u8]> {
        let data = self.buffer.as_mut();
        SocketIdBuffer::new(&mut data[REQ_ID])
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
        MSG_SIZE
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
        if len < MSG_SIZE {
            Err(format!(
                "buffer size is {}, whereas a rule buffer is at least {} long",
                len, MSG_SIZE
            )
            .into())
        } else {
            Ok(())
        }
    }

    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[MSG_FAMILY]
    }

    pub fn state(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[MSG_STATE]
    }

    pub fn timer(&self) -> Option<Timer> {
        let data = self.buffer.as_ref();
        match data[MSG_TIMER] {
            1 => Some(Timer::Retransmit(data[MSG_RETRANS])),
            2 => Some(Timer::KeepAlive(data[MSG_RETRANS])),
            3 => Some(Timer::TimeWait),
            4 => Some(Timer::Probe(data[MSG_RETRANS])),
            _ => None,
        }
    }

    pub fn id(&self) -> SocketIdBuffer<&[u8]> {
        let data = self.buffer.as_ref();
        SocketIdBuffer::new(&data[MSG_ID])
    }

    pub fn expires(&self) -> Option<Duration> {
        let data = self.buffer.as_ref();
        let expires = NativeEndian::read_u32(&data[MSG_EXPIRES]);
        if expires == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(expires)))
        }
    }

    pub fn rqueue(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[MSG_RQUEUE])
    }

    pub fn wqueue(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[MSG_WQUEUE])
    }

    pub fn uid(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[MSG_UID])
    }

    pub fn inode(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[MSG_INODE])
    }

    pub fn attrs(&self) -> RtaIterator<&[u8]> {
        let data = self.buffer.as_ref();
        RtaIterator::new(&data[MSG_ATTRIBUTES])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ResponseBuffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buffer.as_mut();
        data[MSG_FAMILY] = family
    }

    pub fn set_state(&mut self, state: TcpState) {
        let data = self.buffer.as_mut();
        data[MSG_STATE] = state as u8
    }

    pub fn set_timer(&mut self, timer: u8) {
        let data = self.buffer.as_mut();
        data[MSG_TIMER] = timer
    }

    pub fn set_retrans(&mut self, retrans: u8) {
        let data = self.buffer.as_mut();
        data[MSG_RETRANS] = retrans
    }

    pub fn id_mut(&mut self) -> SocketIdBuffer<&mut [u8]> {
        let data = self.buffer.as_mut();
        SocketIdBuffer::new(&mut data[MSG_ID])
    }

    pub fn set_expires(&mut self, expires: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[MSG_EXPIRES], expires)
    }

    pub fn set_rqueue(&mut self, rqueue: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[MSG_RQUEUE], rqueue)
    }

    pub fn set_wqueue(&mut self, wqueue: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[MSG_WQUEUE], wqueue)
    }

    pub fn set_uid(&mut self, uid: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[MSG_UID], uid)
    }

    pub fn set_inode(&mut self, inode: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[MSG_INODE], inode)
    }
}

impl CStruct for TcpInfo {}
impl CStruct for MemInfo {}

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
    Other(u16, Vec<u8>),
}

impl<T: AsRef<[u8]>> ParseableParametrized<Attr, u16> for T {
    fn parse_with_param(&self, ty: u16) -> Result<Attr, DecodeError> {
        use Extension::*;

        let payload = self.as_ref();

        Extension::try_from(ty)
            .and_then(|attr| {
                Ok(match attr {
                    INET_DIAG_MEMINFO if payload.len() >= mem::size_of::<MemInfo>() => {
                        Attr::MemInfo(payload.parse()?)
                    }
                    INET_DIAG_INFO if payload.len() >= mem::size_of::<TcpInfo>() => {
                        Attr::Info(Box::new(payload.parse()?))
                    }
                    INET_DIAG_CONG if !payload.is_empty() => Attr::Conf(
                        CStr::from_bytes_with_nul(payload)
                            .context("invalid name")?
                            .to_str()
                            .context("invalid name")?
                            .to_owned(),
                    ),
                    INET_DIAG_TOS if !payload.is_empty() => Attr::Tos(payload[0]),
                    INET_DIAG_TCLASS if !payload.is_empty() => Attr::TClass(payload[0]),
                    INET_DIAG_SKMEMINFO if payload.len() >= mem::size_of::<SkMemInfo>() => {
                        Attr::SkMemInfo(payload.parse()?)
                    }
                    INET_DIAG_SHUTDOWN if !payload.is_empty() => {
                        Attr::Shutdown(Shutdown::from_bits_truncate(payload[0]))
                    }
                    INET_DIAG_PROTOCOL if !payload.is_empty() => Attr::Protocol(payload[0]),
                    INET_DIAG_SKV6ONLY if !payload.is_empty() => Attr::SkV6Only(payload[0] != 0),
                    INET_DIAG_MARK if payload.len() >= mem::size_of::<u32>() => {
                        Attr::Mark(NativeEndian::read_u32(payload))
                    }
                    INET_DIAG_CLASS_ID if payload.len() >= mem::size_of::<u32>() => {
                        Attr::ClassId(NativeEndian::read_u32(payload))
                    }
                    _ => Attr::Other(ty, payload.to_vec()),
                })
            })
            .or_else(|_| Ok(Attr::Other(ty, payload.to_vec())))
    }
}
