use std::ffi::CStr;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;
use std::time::Duration;

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};

use crate::sock_diag::{
    inet_diag::{extension, extension::*, tcp_state, tcp_state::*},
    unix_diag::{attribute, show::*, unix_diag_rqlen, unix_diag_vfs, unix_state},
};
use crate::{DecodeError, Field, ParseableParametrized, Rest};

const fn array_of<T>(start: usize, len: usize) -> Field {
    start..(start + mem::size_of::<T>() * len)
}

const IDIAG_SPORT: Field = 0..2;
const IDIAG_DPORT: Field = 2..4;
const IDIAG_SRC: Field = array_of::<u32>(4, 4);
const IDIAG_DST: Field = array_of::<u32>(20, 4);
const IDIAG_IF: Field = 36..40;
const IDIAG_COOKIE: Field = array_of::<u32>(40, 2);
const IDIAG_ID_SIZE: usize = IDIAG_COOKIE.end;

const INET_DIAG_NOCOOKIE: u64 = !0;

const SDIAG_FAMILY: usize = 0;
const SDIAG_PROTOCOL: usize = 1;
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

pub type TcpState = tcp_state;

bitflags! {
    pub struct TcpStates: u32 {
        const Established = 1 << TCP_ESTABLISHED as u8;
        const SynSent = 1 <<TCP_SYN_SENT as u8;
        const SynRecv = 1 << TCP_SYN_RECV as u8;
        const FinWait1 = 1 << TCP_FIN_WAIT1 as u8;
        const FinWait2 = 1 << TCP_FIN_WAIT2 as u8;
        const TimeWait = 1 << TCP_TIME_WAIT as u8;
        const Close = 1 << TCP_CLOSE as u8;
        const CloseWait = 1 << TCP_CLOSE_WAIT as u8;
        const LastAck = 1 << TCP_LAST_ACK as u8;
        const Listen = 1 << TCP_LISTEN as u8;
        const Closing = 1 << TCP_CLOSING as u8;
    }
}

impl Default for TcpStates {
    fn default() -> Self {
        TcpStates::all()
    }
}

bitflags! {
    pub struct UnixStates: u32 {
        const Established = 1 << TCP_ESTABLISHED as u8;
        const Listen = 1 << TCP_LISTEN as u8;
    }
}

impl Default for UnixStates {
    fn default() -> Self {
        UnixStates::all()
    }
}

bitflags! {
    pub struct Extension: u8 {
        const MemInfo = 1 << (INET_DIAG_MEMINFO as u16 - 1);
        const Info = 1 << (INET_DIAG_INFO as u16 - 1);
        const VegasInfo = 1 << (INET_DIAG_VEGASINFO as u16 - 1);
        const Conf = 1 << (INET_DIAG_CONG as u16 - 1);
        const ToS = 1 << (INET_DIAG_TOS as u16 - 1);
        const TClass = 1 << (INET_DIAG_TCLASS as u16 - 1);
        const SkMemInfo = 1 << (INET_DIAG_SKMEMINFO as u16 - 1);
        const Shutdown = 1 << (INET_DIAG_SHUTDOWN as u16 - 1);
    }
}

impl Default for Extension {
    fn default() -> Self {
        Extension::empty()
    }
}

bitflags! {
    pub struct Show: u32 {
        const Name = UDIAG_SHOW_NAME as u32;
        const Vfs = UDIAG_SHOW_VFS as u32;
        const Peer = UDIAG_SHOW_PEER as u32;
        const Icons = UDIAG_SHOW_ICONS as u32;
        const RecvQueueLen = UDIAG_SHOW_RQLEN as u32;
        const MemInfo = UDIAG_SHOW_MEMINFO as u32;
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
        let cookie = u64::from(cookie[0]) + u64::from(cookie[1]) << 32;

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
pub struct InetDiagReqV2Buffer<T> {
    buffer: T,
}

impl<T> InetDiagReqV2Buffer<T> {
    pub fn new(buffer: T) -> InetDiagReqV2Buffer<T> {
        InetDiagReqV2Buffer { buffer }
    }

    pub const fn len() -> usize {
        IDIAG_REQ_SIZE
    }
}

impl<T: AsRef<[u8]>> InetDiagReqV2Buffer<T> {
    pub fn family(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SDIAG_FAMILY]
    }
    pub fn protocol(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SDIAG_PROTOCOL]
    }
    pub fn extensions(&self) -> Extension {
        let data = self.buffer.as_ref();
        Extension::from_bits_truncate(data[IDIAG_REQ_EXT])
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

impl<T: AsRef<[u8]> + AsMut<[u8]>> InetDiagReqV2Buffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buffer.as_mut();
        data[SDIAG_FAMILY] = family
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        let data = self.buffer.as_mut();
        data[SDIAG_PROTOCOL] = protocol
    }

    pub fn set_extensions(&mut self, ext: Extension) {
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
pub struct InetDiagMsgBuffer<T> {
    buffer: T,
}

impl<T> InetDiagMsgBuffer<T> {
    pub fn new(buffer: T) -> InetDiagMsgBuffer<T> {
        InetDiagMsgBuffer { buffer }
    }

    pub const fn len() -> usize {
        IDIAG_MSG_SIZE
    }
}

impl<T: AsRef<[u8]>> InetDiagMsgBuffer<T> {
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

    pub fn state(&self) -> tcp_state {
        let data = self.buffer.as_ref();
        tcp_state::from(data[IDIAG_MSG_STATE])
    }

    pub fn timer(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[IDIAG_MSG_TIMER]
    }

    pub fn retrans(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[IDIAG_MSG_RETRANS]
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
            Some(Duration::from_millis(expires as u64))
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

impl<T: AsRef<[u8]> + AsMut<[u8]>> InetDiagMsgBuffer<T> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtaIterator<T> {
    position: usize,
    buffer: T,
}

impl<T> RtaIterator<T> {
    pub fn new(buffer: T) -> Self {
        RtaIterator {
            position: 0,
            buffer,
        }
    }
}

const RTA_ALIGNTO: usize = 4;
const RTA_HDR_LEN: usize = mem::size_of::<u16>() * 2;

const RTA_LENGTH: Field = 0..2;
const RTA_TYPE: Field = 2..4;

impl<'buffer, T: AsRef<[u8]> + ?Sized + 'buffer> Iterator for RtaIterator<&'buffer T> {
    type Item = (u16, &'buffer [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        // rtattr are aligned on 4 bytes boundaries, so we make sure we ignore any potential padding.
        let offset = self.position % RTA_ALIGNTO;
        if offset != 0 {
            self.position += RTA_ALIGNTO - offset;
        }

        let data = self.buffer.as_ref();

        if self.position >= data.len() || data.len() < RTA_HDR_LEN {
            return None;
        }

        let data = &data[self.position..];
        let len = NativeEndian::read_u16(&data[RTA_LENGTH]) as usize;
        let ty = NativeEndian::read_u16(&data[RTA_TYPE]);

        if len >= data.len() {
            return None;
        }

        let payload = &data[RTA_HDR_LEN..len];

        trace!(
            "parse {:?} extension at {} with {} bytes: {:?}",
            ty,
            self.position,
            payload.len(),
            payload
        );

        self.position += len;

        Some((ty, payload))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InetDiagAttr {
    MemInfo(MemInfo),
    Info(Box<TcpInfo>),
    Conf(String),
    Tos(u8),
    TClass(u8),
    SkMemInfo(SkMemInfo),
    Shutdown(Shutdown),
    Protocol(u8),
    SkV6Only(bool),
    Mark(u32),
    ClassId(u32),
    Other(extension, Vec<u8>),
}

impl<T: AsRef<[u8]>> ParseableParametrized<InetDiagAttr, extension> for T {
    fn parse_with_param(&self, ty: extension) -> Result<InetDiagAttr, DecodeError> {
        let payload = self.as_ref();

        Ok(match ty {
            INET_DIAG_MEMINFO if payload.len() >= mem::size_of::<MemInfo>() => {
                InetDiagAttr::MemInfo(MemInfo::parse(payload))
            }
            INET_DIAG_INFO if payload.len() >= mem::size_of::<TcpInfo>() => {
                InetDiagAttr::Info(Box::new(TcpInfo::parse(payload)))
            }
            INET_DIAG_CONG => InetDiagAttr::Conf(unsafe {
                CStr::from_bytes_with_nul_unchecked(payload)
                    .to_string_lossy()
                    .into_owned()
            }),
            INET_DIAG_TOS if payload.len() >= 1 => InetDiagAttr::Tos(payload[0]),
            INET_DIAG_TCLASS if payload.len() >= 1 => InetDiagAttr::TClass(payload[0]),
            INET_DIAG_SKMEMINFO if payload.len() > mem::size_of::<SkMemInfo>() => {
                InetDiagAttr::SkMemInfo(SkMemInfo::parse(payload))
            }
            INET_DIAG_SHUTDOWN if payload.len() >= 1 => {
                InetDiagAttr::Shutdown(Shutdown::from_bits_truncate(payload[0] & SHUTDOWN_MASK))
            }
            INET_DIAG_PROTOCOL if payload.len() >= 1 => InetDiagAttr::Protocol(payload[0]),
            INET_DIAG_SKV6ONLY if payload.len() >= 1 => InetDiagAttr::SkV6Only(payload[0] != 0),
            INET_DIAG_MARK if payload.len() >= 4 => {
                InetDiagAttr::Mark(NativeEndian::read_u32(payload))
            }
            INET_DIAG_CLASS_ID if payload.len() >= 4 => {
                InetDiagAttr::ClassId(NativeEndian::read_u32(payload))
            }
            _ => InetDiagAttr::Other(ty, payload.to_vec()),
        })
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MemInfo {
    pub rmem: u32,
    pub wmem: u32,
    pub fmem: u32,
    pub tmem: u32,
}

impl MemInfo {
    pub fn parse(data: &[u8]) -> Self {
        unsafe { ptr::read(data.as_ptr() as *const MemInfo) }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcpInfo {
    pub tcpi_state: u8,
    pub tcpi_ca_state: u8,
    pub tcpi_retransmits: u8,
    pub tcpi_probes: u8,
    pub tcpi_backoff: u8,
    pub tcpi_options: u8,
    pub tcpi_wscale: u8,
    pub tcpi_delivery_rate_app_limited: u8,

    pub tcpi_rto: u32,
    pub tcpi_ato: u32,
    pub tcpi_snd_mss: u32,
    pub tcpi_rcv_mss: u32,

    pub tcpi_unacked: u32,
    pub tcpi_sacked: u32,
    pub tcpi_lost: u32,
    pub tcpi_retrans: u32,
    pub tcpi_fackets: u32,

    // Times.
    pub tcpi_last_data_sent: u32,
    pub tcpi_last_ack_sent: u32,
    pub tcpi_last_data_recv: u32,
    pub tcpi_last_ack_recv: u32,

    // Metrics.
    pub tcpi_pmtu: u32,
    pub tcpi_rcv_ssthresh: u32,
    pub tcpi_rtt: u32,
    pub tcpi_rttvar: u32,
    pub tcpi_snd_ssthresh: u32,
    pub tcpi_snd_cwnd: u32,
    pub tcpi_advmss: u32,
    pub tcpi_reordering: u32,

    pub tcpi_rcv_rtt: u32,
    pub tcpi_rcv_space: u32,

    pub tcpi_total_retrans: u32,

    pub tcpi_pacing_rate: u64,
    pub tcpi_max_pacing_rate: u64,
    pub tcpi_bytes_acked: u64,    // RFC4898 tcpEStatsAppHCThruOctetsAcked
    pub tcpi_bytes_received: u64, // RFC4898 tcpEStatsAppHCThruOctetsReceived
    pub tcpi_segs_out: u32,       // RFC4898 tcpEStatsPerfSegsOut
    pub tcpi_segs_in: u32,        // RFC4898 tcpEStatsPerfSegsIn

    pub tcpi_notsent_bytes: u32,
    pub tcpi_min_rtt: u32,
    pub tcpi_data_segs_in: u32,  // RFC4898 tcpEStatsDataSegsIn
    pub tcpi_data_segs_out: u32, // RFC4898 tcpEStatsDataSegsOut

    pub tcpi_delivery_rate: u64,

    pub tcpi_busy_time: u64,      // Time (usec) busy sending data
    pub tcpi_rwnd_limited: u64,   // Time (usec) limited by receive window
    pub tcpi_sndbuf_limited: u64, // Time (usec) limited by send buffer

    pub tcpi_delivered: u32,
    pub tcpi_delivered_ce: u32,

    pub tcpi_bytes_sent: u64,    // RFC4898 tcpEStatsPerfHCDataOctetsOut
    pub tcpi_bytes_retrans: u64, // RFC4898 tcpEStatsPerfOctetsRetrans
    pub tcpi_dsack_dups: u32,    // RFC4898 tcpEStatsStackDSACKDups
    pub tcpi_reord_seen: u32,    // reordering events seen
}

impl TcpInfo {
    pub fn parse(data: &[u8]) -> Self {
        unsafe { ptr::read(data.as_ptr() as *const TcpInfo) }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SkMemInfo {
    pub rmem_alloc: u32,
    pub recvbuf: u32,
    pub wmem_alloc: u32,
    pub sndbuf: u32,
    pub fwd_alloc: u32,
    pub wmem_queued: u32,
    pub optmem: u32,
    pub backlog: u32,
    pub drops: u32,
}

impl SkMemInfo {
    pub fn parse(data: &[u8]) -> Self {
        unsafe { ptr::read(data.as_ptr() as *const SkMemInfo) }
    }
}

bitflags! {
    pub struct Shutdown: u8 {
        const None = 0;
        const Recv = RCV_SHUTDOWN;
        const Send = SEND_SHUTDOWN;
    }
}

const SHUTDOWN_MASK: u8 = 3;
const RCV_SHUTDOWN: u8 = 1;
const SEND_SHUTDOWN: u8 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnixDiagReqBuffer<T> {
    buffer: T,
}

impl<T> UnixDiagReqBuffer<T> {
    pub fn new(buffer: T) -> UnixDiagReqBuffer<T> {
        UnixDiagReqBuffer { buffer }
    }

    pub const fn len() -> usize {
        UDIAG_REQ_SIZE
    }
}

impl<T: AsRef<[u8]>> UnixDiagReqBuffer<T> {
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
        let cookie = u64::from(cookie[0]) + u64::from(cookie[1]) << 32;

        if cookie == INET_DIAG_NOCOOKIE {
            None
        } else {
            Some(cookie)
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UnixDiagReqBuffer<T> {
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
pub struct UnixDiagMsgBuffer<T> {
    buffer: T,
}

impl<T> UnixDiagMsgBuffer<T> {
    pub fn new(buffer: T) -> UnixDiagMsgBuffer<T> {
        UnixDiagMsgBuffer { buffer }
    }

    pub const fn len() -> usize {
        UDIAG_MSG_SIZE
    }
}

impl<T: AsRef<[u8]>> UnixDiagMsgBuffer<T> {
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
    pub fn state(&self) -> unix_state {
        let data = self.buffer.as_ref();
        unix_state::from(data[UDIAG_MSG_STATE])
    }
    pub fn inode(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[UDIAG_MSG_INO])
    }
    pub fn cookie(&self) -> Option<u64> {
        let data = self.buffer.as_ref();
        let mut cookie = [0u32; 2];
        NativeEndian::read_u32_into(&data[UDIAG_MSG_COOKIE], &mut cookie);
        let cookie = u64::from(cookie[0]) + u64::from(cookie[1]) << 32;

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UnixDiagAttr {
    Name(String),
    Vfs(unix_diag_vfs),
    Peer(u32),
    Icons(Vec<u32>),
    RecvQueueLen(unix_diag_rqlen),
    MemInfo(SkMemInfo),
    Shutdown(Shutdown),
    Other(attribute, Vec<u8>),
}

impl<T: AsRef<[u8]>> ParseableParametrized<UnixDiagAttr, attribute> for T {
    fn parse_with_param(&self, ty: attribute) -> Result<UnixDiagAttr, DecodeError> {
        use attribute::*;

        let payload = self.as_ref();

        Ok(match ty {
            UNIX_DIAG_NAME => UnixDiagAttr::Name(unsafe {
                CStr::from_bytes_with_nul_unchecked(payload)
                    .to_string_lossy()
                    .into_owned()
            }),
            UNIX_DIAG_VFS if payload.len() >= 8 => UnixDiagAttr::Vfs(unix_diag_vfs {
                udiag_vfs_ino: NativeEndian::read_u32(&payload[0..4]),
                udiag_vfs_dev: NativeEndian::read_u32(&payload[4..8]),
            }),
            UNIX_DIAG_PEER if payload.len() >= 4 => {
                UnixDiagAttr::Peer(NativeEndian::read_u32(payload))
            }
            UNIX_DIAG_ICONS => {
                let mut icons = vec![0; payload.len() / 4];
                NativeEndian::read_u32_into(&payload[..icons.len() * 4], icons.as_mut_slice());
                UnixDiagAttr::Icons(icons)
            }
            UNIX_DIAG_RQLEN if payload.len() >= 8 => UnixDiagAttr::RecvQueueLen(unix_diag_rqlen {
                udiag_rqueue: NativeEndian::read_u32(&payload[0..4]),
                udiag_wqueue: NativeEndian::read_u32(&payload[4..8]),
            }),
            UNIX_DIAG_MEMINFO if payload.len() > mem::size_of::<SkMemInfo>() => {
                UnixDiagAttr::MemInfo(SkMemInfo::parse(payload))
            }
            UNIX_DIAG_SHUTDOWN if payload.len() >= 1 => {
                UnixDiagAttr::Shutdown(Shutdown::from_bits_truncate(payload[0] & SHUTDOWN_MASK))
            }
            _ => UnixDiagAttr::Other(ty, payload.to_vec()),
        })
    }
}
