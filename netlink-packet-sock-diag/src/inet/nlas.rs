// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};

pub use crate::utils::nla::{DefaultNla, NlaBuffer, NlasIterator};

use crate::{
    constants::*,
    parsers::{parse_string, parse_u32, parse_u8},
    traits::{Emitable, Parseable},
    DecodeError,
};

pub const LEGACY_MEM_INFO_LEN: usize = 16;

buffer!(LegacyMemInfoBuffer(LEGACY_MEM_INFO_LEN) {
    receive_queue: (u32, 0..4),
    bottom_send_queue: (u32, 4..8),
    cache: (u32, 8..12),
    send_queue: (u32, 12..16)
});

/// In recent Linux kernels, this NLA is not used anymore to report
/// AF_INET and AF_INET6 sockets memory information. See [`MemInfo`]
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMemInfo {
    /// Amount of data in the receive queue.
    pub receive_queue: u32,
    /// Amount of data that is queued by TCP but not yet sent.
    pub bottom_send_queue: u32,
    /// Amount of memory scheduled for future use (TCP only).
    pub cache: u32,
    /// Amount of data in the send queue.
    pub send_queue: u32,
}

impl<T: AsRef<[u8]>> Parseable<LegacyMemInfoBuffer<T>> for LegacyMemInfo {
    fn parse(buf: &LegacyMemInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            receive_queue: buf.receive_queue(),
            bottom_send_queue: buf.bottom_send_queue(),
            cache: buf.cache(),
            send_queue: buf.send_queue(),
        })
    }
}

impl Emitable for LegacyMemInfo {
    fn buffer_len(&self) -> usize {
        LEGACY_MEM_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = LegacyMemInfoBuffer::new(buf);
        buf.set_receive_queue(self.receive_queue);
        buf.set_bottom_send_queue(self.bottom_send_queue);
        buf.set_cache(self.cache);
        buf.set_send_queue(self.send_queue);
    }
}

pub const MEM_INFO_LEN: usize = 36;

// FIXME: the last 2 fields are not present on old linux kernels. We
// should support optional fields in the `buffer!` macro.
buffer!(MemInfoBuffer(MEM_INFO_LEN) {
    receive_queue: (u32, 0..4),
    receive_queue_max: (u32, 4..8),
    bottom_send_queues: (u32, 8..12),
    send_queue_max: (u32, 12..16),
    cache: (u32, 16..20),
    send_queue: (u32, 20..24),
    options: (u32, 24..28),
    backlog_queue_length: (u32, 28..32),
    drops: (u32, 32..36),
});

/// Socket memory information. To understand this information, one
/// must understand how the memory allocated for the send and receive
/// queues of a socket is managed.
///
/// # Warning
///
/// This data structure is not well documented. The explanations given
/// here are the results of my personal research on this topic, but I
/// am by no mean an expert in Linux networking, so take this
/// documentation with a huge grain of salt. Please report any error
/// you may notice. Here are the references I used:
///
/// - [https://wiki.linuxfoundation.org/networking/sk_buff](a short introduction to `sk_buff`, the struct used in the kernel to store packets)
/// - [vger.kernel.org has a lot of documentation about the low level network stack APIs](http://vger.kernel.org/~davem/skb_data.html)
/// - [thorough high level explanation of buffering in the network stack](https://www.coverfire.com/articles/queueing-in-the-linux-network-stack/)
/// - [understanding the backlog queue](http://veithen.io/2014/01/01/how-tcp-backlog-works-in-linux.html)
/// - [high level explanation of packet reception](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/performance_tuning_guide/s-network-packet-reception)
/// - [a StackExchange question about the different send queues used by a socket](https://unix.stackexchange.com/questions/551444/what-is-the-difference-between-sock-sk-wmem-alloc-and-sock-sk-wmem-queued)
/// - other useful resources: [here](https://www.cl.cam.ac.uk/~pes20/Netsem/linuxnet.pdf) and [here](https://people.cs.clemson.edu/~westall/853/notes/skbuff.pdf)
/// - [explanation of the socket backlog queue](https://medium.com/@c0ngwang/the-design-of-lock-sock-in-linux-kernel-69c3406e504b)
///
/// # Linux networking in a nutshell
///
/// The network stack uses multiple queues, both for sending an
/// receiving data. Let's start with the simplest case: packet
/// receptions.
///
/// When data is received, it is first handled by the device driver
/// and put in the device driver queue. The kernel then move the
/// packet to the socket receive queue (also called _receive
/// buffer_). Finally, this application reads it (with `recv`, `read`
/// or `recvfrom`) and the packet is dequeued.
///
/// Sending packet it slightly more complicated and the exact workflow
/// may differ from one protocol to the other so we'll just give a
/// high level overview. When an application sends data, a packet is
/// created and stored in the socket send queue (also called _send
/// buffer_). It is then passed down to the QDisc (Queuing
/// Disciplines) queue. The QDisc facility enables quality of service:
/// if some data is more urgent to transmit than other, QDisc will
/// make sure it is sent in priority. Finally, the data is put on the
/// device driver queue to be sent out.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MemInfo {
    /// Memory currently allocated for the socket's receive
    /// queue. This attribute is known as `sk_rmem_alloc` in the
    /// kernel.
    pub receive_queue: u32,
    /// Maximum amount of memory that can be allocated for the
    /// socket's receive queue. This is set by `SO_RCVBUF`. This is
    /// _not_ the amount of memory currently allocated. This attribute
    /// is known as `sk_rcvbuf` in the kernel.
    pub receive_queue_max: u32,
    /// Memory currently allocated for the socket send queue. This
    /// attribute is known as `sk_wmem_queued` in the kernel. This
    /// does does not account for data that have been passed down the
    /// network stack (i.e. to the QDisc and device driver queues),
    /// which is reported by the `bottow_send_queue` (known as
    /// `sk_wmem_alloc` in the kernel).
    ///
    /// For a TCP socket, if the congestion window is small, the
    /// kernel will move the data fron the socket send queue to the
    /// QDisc queues more slowly. Thus, if the process sends of lot of
    /// data, the socket send queue (which memory is tracked by
    /// `sk_wmem_queued`) will grow while `sk_wmem_alloc` will remain
    /// small.
    pub send_queue: u32,
    /// Maximum amount of memory (in bytes) that can be allocated for
    /// this socket's send queue. This is set by `SO_SNDBUF`. This is
    /// _not_ the amount of memory currently allocated. This attribute
    /// is known as `sk_sndbuf` in the kernel.
    pub send_queue_max: u32,
    /// Memory used for packets that have been passed down the network
    /// stack, i.e. that are either in the QDisc or device driver
    /// queues. This attribute is known as `sk_wmem_alloc` in the
    /// kernel. See also [`send_queue`].
    pub bottom_send_queues: u32,
    /// The amount of memory already allocated for this socket but
    /// currently unused. When more memory is needed either for
    /// sending or for receiving data, it will be taken from this
    /// pool. This attribute is known as `sk_fwd_alloc` in the kernel.
    pub cache: u32,
    /// The amount of memory allocated for storing socket options, for
    /// instance the key for TCP MD5 signature. This attribute is
    /// known as `sk_optmem` in the kernel.
    pub options: u32,
    /// The length of the backlog queue. When the process is using the
    /// socket, the socket is locked so the kernel cannot enqueue new
    /// packets in the receive queue. To avoid blocking the bottom
    /// half of network stack waiting for the process to release the
    /// socket, the packets are enqueued in the backlog queue. Upon
    /// releasing the socket, those packets are processed and put in
    /// the regular receive queue.
    // FIXME: this should be an Option because it's not present on old
    // linux kernels.
    pub backlog_queue_length: u32,
    /// The amount of packets dropped. Depending on the kernel
    /// version, this field may not be present.
    // FIXME: this should be an Option because it's not present on old
    // linux kernels.
    pub drops: u32,
}

impl<T: AsRef<[u8]>> Parseable<MemInfoBuffer<T>> for MemInfo {
    fn parse(buf: &MemInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            receive_queue: buf.receive_queue(),
            receive_queue_max: buf.receive_queue_max(),
            bottom_send_queues: buf.bottom_send_queues(),
            send_queue_max: buf.send_queue_max(),
            cache: buf.cache(),
            send_queue: buf.send_queue(),
            options: buf.options(),
            backlog_queue_length: buf.backlog_queue_length(),
            drops: buf.drops(),
        })
    }
}

impl Emitable for MemInfo {
    fn buffer_len(&self) -> usize {
        MEM_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = MemInfoBuffer::new(buf);
        buf.set_receive_queue(self.receive_queue);
        buf.set_receive_queue_max(self.receive_queue_max);
        buf.set_bottom_send_queues(self.bottom_send_queues);
        buf.set_send_queue_max(self.send_queue_max);
        buf.set_cache(self.cache);
        buf.set_send_queue(self.send_queue);
        buf.set_options(self.options);
        buf.set_backlog_queue_length(self.backlog_queue_length);
        buf.set_drops(self.drops);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    /// The memory information of the socket. This attribute is
    /// similar to `Nla::MemInfo` but provides less information. On
    /// recent kernels, `Nla::MemInfo` is used instead.
    // ref: https://patchwork.ozlabs.org/patch/154816/
    LegacyMemInfo(LegacyMemInfo),
    /// the TCP information
    TcpInfo(TcpInfo),
    /// the congestion control algorithm used
    Congestion(String),
    /// the TOS of the socket.
    Tos(u8),
    /// the traffic class of the socket.
    Tc(u8),
    /// The memory information of the socket
    MemInfo(MemInfo),
    /// Shutown state: one of [`SHUT_RD`], [`SHUT_WR`] or [`SHUT_RDWR`]
    Shutdown(u8),
    /// The protocol
    Protocol(u8),
    /// Whether the socket is IPv6 only
    SkV6Only(bool),
    /// The mark of the socket.
    Mark(u32),
    /// The class ID of the socket.
    ClassId(u32),
    /// other attribute
    Other(DefaultNla),
}

impl crate::utils::nla::Nla for Nla {
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            LegacyMemInfo(_) => LEGACY_MEM_INFO_LEN,
            TcpInfo(_) => TCP_INFO_LEN,
            // +1 because we need to append a null byte
            Congestion(ref s) => s.as_bytes().len() + 1,
            Tos(_) | Tc(_) | Shutdown(_) | Protocol(_) | SkV6Only(_) => 1,
            MemInfo(_) => MEM_INFO_LEN,
            Mark(_) | ClassId(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            LegacyMemInfo(_) => INET_DIAG_MEMINFO,
            TcpInfo(_) => INET_DIAG_INFO,
            Congestion(_) => INET_DIAG_CONG,
            Tos(_) => INET_DIAG_TOS,
            Tc(_) => INET_DIAG_TCLASS,
            MemInfo(_) => INET_DIAG_SKMEMINFO,
            Shutdown(_) => INET_DIAG_SHUTDOWN,
            Protocol(_) => INET_DIAG_PROTOCOL,
            SkV6Only(_) => INET_DIAG_SKV6ONLY,
            Mark(_) => INET_DIAG_MARK,
            ClassId(_) => INET_DIAG_CLASS_ID,
            Other(ref attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            LegacyMemInfo(ref value) => value.emit(buffer),
            TcpInfo(ref value) => value.emit(buffer),
            Congestion(ref s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Tos(b) | Tc(b) | Shutdown(b) | Protocol(b) => buffer[0] = b,
            SkV6Only(value) => buffer[0] = value.into(),
            MemInfo(ref value) => value.emit(buffer),
            Mark(value) | ClassId(value) => NativeEndian::write_u32(buffer, value),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            INET_DIAG_MEMINFO => {
                let err = "invalid INET_DIAG_MEMINFO value";
                let buf = LegacyMemInfoBuffer::new_checked(payload).context(err)?;
                Self::LegacyMemInfo(LegacyMemInfo::parse(&buf).context(err)?)
            }
            INET_DIAG_INFO => {
                let err = "invalid INET_DIAG_INFO value";
                let buf = TcpInfoBuffer::new_checked(payload).context(err)?;
                Self::TcpInfo(TcpInfo::parse(&buf).context(err)?)
            }
            INET_DIAG_CONG => {
                Self::Congestion(parse_string(payload).context("invalid INET_DIAG_CONG value")?)
            }
            INET_DIAG_TOS => Self::Tos(parse_u8(payload).context("invalid INET_DIAG_TOS value")?),
            INET_DIAG_TCLASS => {
                Self::Tc(parse_u8(payload).context("invalid INET_DIAG_TCLASS value")?)
            }
            INET_DIAG_SKMEMINFO => {
                let err = "invalid INET_DIAG_SKMEMINFO value";
                let buf = MemInfoBuffer::new_checked(payload).context(err)?;
                Self::MemInfo(MemInfo::parse(&buf).context(err)?)
            }
            INET_DIAG_SHUTDOWN => {
                Self::Shutdown(parse_u8(payload).context("invalid INET_DIAG_SHUTDOWN value")?)
            }
            INET_DIAG_PROTOCOL => {
                Self::Protocol(parse_u8(payload).context("invalid INET_DIAG_PROTOCOL value")?)
            }
            INET_DIAG_SKV6ONLY => {
                Self::SkV6Only(parse_u8(payload).context("invalid INET_DIAG_SKV6ONLY value")? != 0)
            }
            INET_DIAG_MARK => {
                Self::Mark(parse_u32(payload).context("invalid INET_DIAG_MARK value")?)
            }
            INET_DIAG_CLASS_ID => {
                Self::ClassId(parse_u32(payload).context("invalid INET_DIAG_CLASS_ID value")?)
            }
            kind => {
                Self::Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?)
            }
        })
    }
}

pub const TCP_INFO_LEN: usize = 232;

buffer!(TcpInfoBuffer(TCP_INFO_LEN) {
    // State of the TCP connection. This should be set to one of the
    // `TCP_*` constants: `TCP_ESTABLISHED`, `TCP_SYN_SENT`, etc. This
    // attribute is known as `tcpi_state` in the kernel.
    state: (u8, 0),
    // State of congestion avoidance. Sender's congestion state
    // indicating normal or abnormal situations in the last round of
    // packets sent. The state is driven by the ACK information and
    // timer events. This should be set to one of the `TCP_CA_*`
    // constants. This attribute is known as `tcpi_ca_state` in the
    // kernel.
    congestion_avoidance_state: (u8, 1),
    // Number of retranmissions on timeout invoked. This attribute is
    // known as `tcpi_retransmits` in the kernel.
    retransmits: (u8, 2),
    // Number of window or keep alive probes sent. This attribute is
    // known as `tcpi_probes`.
    probes: (u8, 3),
    // Number of times the retransmission backoff timer invoked
    backoff: (u8, 4),
    options: (u8, 5),
    wscale: (u8, 6),
    delivery_rate_app_limited: (u8, 7),

    rto: (u32, 8..12),
    ato: (u32, 12..16),
    snd_mss: (u32, 16..20),
    rcv_mss: (u32, 20..24),

    unacked: (u32, 24..28),
    sacked: (u32, 28..32),
    lost: (u32, 32..36),
    retrans: (u32, 36..40),
    fackets: (u32, 40..44),

    // Times
    last_data_sent: (u32, 44..48),
    last_ack_sent: (u32, 48..52),
    last_data_recv: (u32, 52..56),
    last_ack_recv: (u32, 56..60),

    // Metrics
    pmtu: (u32, 60..64),
    rcv_ssthresh: (u32, 64..68),
    rtt: (u32, 68..72),
    rttvar: (u32, 72..76),
    snd_ssthresh: (u32, 76..80),
    snd_cwnd: (u32, 80..84),
    advmss: (u32, 84..88),
    reordering: (u32, 88..92),

    rcv_rtt: (u32, 92..96),
    rcv_space: (u32, 96..100),

    total_retrans: (u32, 100..104),

    pacing_rate: (u64, 104..112),
    max_pacing_rate: (u64, 112..120),
    bytes_acked: (u64, 120..128),       // RFC4898 tcpEStatsAppHCThruOctetsAcked
    bytes_received: (u64, 128..136),    // RFC4898 tcpEStatsAppHCThruOctetsReceived
    segs_out: (u32, 136..140),          // RFC4898 tcpEStatsPerfSegsOut
    segs_in: (u32, 140..144),           // RFC4898 tcpEStatsPerfSegsIn

    notsent_bytes: (u32, 144..148),
    min_rtt: (u32, 148..152),
    data_segs_in: (u32, 152..156),      // RFC4898 tcpEStatsDataSegsIn
    data_segs_out: (u32, 156..160),     // RFC4898 tcpEStatsDataSegsOut

    delivery_rate: (u64, 160..168),

    busy_time: (u64, 168..176),         // Time (usec) busy sending data
    rwnd_limited: (u64, 176..184),      // Time (usec) limited by receive window
    sndbuf_limited: (u64, 184..192),    // Time (usec) limited by send buffer

    delivered: (u32, 192..196),
    delivered_ce: (u32, 196..200),

    bytes_sent: (u64, 200..208),       // RFC4898 tcpEStatsPerfHCDataOctetsOut
    bytes_retrans: (u64, 208..216),    // RFC4898 tcpEStatsPerfOctetsRetrans
    dsack_dups: (u32,   216..220),     // RFC4898 tcpEStatsStackDSACKDups
    reord_seen: (u32,   220..224),     // reordering events seen
    // TODO: These are pretty recent addition, we should hide them behind
    // `#[cfg]` flag
    rcv_ooopack: (u32, 224..228),     // Out-of-order packets received
    snd_wnd: (u32, 228..232),         // peer's advertised receive window after scaling (bytes)
});

// https://unix.stackexchange.com/questions/542712/detailed-output-of-ss-command

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpInfo {
    /// State of the TCP connection: one of `TCP_ESTABLISHED`,
    /// `TCP_SYN_SENT`, `TP_SYN_RECV`, `TCP_FIN_WAIT1`,
    /// `TCP_FIN_WAIT2` `TCP_TIME_WAIT`, `TCP_CLOSE`,
    /// `TCP_CLOSE_WAIT`, `TCP_LAST_ACK` `TCP_LISTEN`, `TCP_CLOSING`.
    pub state: u8,
    /// Congestion algorithm state: one of `TCP_CA_OPEN`,
    /// `TCP_CA_DISORDER`, `TCP_CA_CWR`, `TCP_CA_RECOVERY`,
    /// `TCP_CA_LOSS`
    pub ca_state: u8,
    ///
    pub retransmits: u8,
    pub probes: u8,
    pub backoff: u8,
    pub options: u8,
    // First 4 bits are snd_wscale, last 4 bits rcv_wscale
    pub wscale: u8,
    /// A boolean indicating if the goodput was measured when the
    /// socket's throughput was limited by the sending application.
    /// tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2
    pub delivery_rate_app_limited: u8,

    /// Value of the RTO (Retransmission TimeOut) timer. This value is
    /// calculated using the RTT.
    pub rto: u32,
    /// Value of the ATO (ACK TimeOut) timer.
    pub ato: u32,
    /// MSS (Maximum Segment Size). Not shure how it differs from
    /// `advmss`.
    pub snd_mss: u32,
    /// MSS (Maximum Segment Size) advertised by peer
    pub rcv_mss: u32,

    /// Number of segments that have not been ACKnowledged yet, ie the
    /// number of in-flight segments.
    pub unacked: u32,
    /// Number of segments that have been SACKed
    pub sacked: u32,
    /// Number of segments that have been lost
    pub lost: u32,
    /// Number of segments that have been retransmitted
    pub retrans: u32,
    /// Number of segments that have been FACKed
    pub fackets: u32,

    pub last_data_sent: u32,
    pub last_ack_sent: u32,
    pub last_data_recv: u32,
    pub last_ack_recv: u32,

    pub pmtu: u32,
    pub rcv_ssthresh: u32,
    /// RTT (Round Trip Time). There RTT is the time between the
    /// moment a segment is sent out and the moment it is
    /// acknowledged. There are different kinds of RTT values, and I
    /// don't know which one this value corresponds to: mRTT (measured
    /// RTT), sRTT (smoothed RTT), RTTd (deviated RTT), etc.
    pub rtt: u32,
    /// RTT variance (or variation?)
    pub rttvar: u32,
    /// Slow-Start Threshold
    pub snd_ssthresh: u32,
    /// Size of the congestion window
    pub snd_cwnd: u32,
    /// MSS advertised by this peer
    pub advmss: u32,

    pub reordering: u32,

    pub rcv_rtt: u32,
    pub rcv_space: u32,

    pub total_retrans: u32,

    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub bytes_acked: u64,    // RFC4898 tcpEStatsAppHCThruOctetsAcked
    pub bytes_received: u64, // RFC4898 tcpEStatsAppHCThruOctetsReceived
    pub segs_out: u32,       // RFC4898 tcpEStatsPerfSegsOut
    pub segs_in: u32,        // RFC4898 tcpEStatsPerfSegsIn

    pub notsent_bytes: u32,
    pub min_rtt: u32,
    pub data_segs_in: u32,  // RFC4898 tcpEStatsDataSegsIn
    pub data_segs_out: u32, // RFC4898 tcpEStatsDataSegsOut

    /// The most recent goodput, as measured by tcp_rate_gen(). If the
    /// socket is limited by the sending application (e.g., no data to
    /// send), it reports the highest measurement instead of the most
    /// recent. The unit is bytes per second (like other rate fields
    /// in tcp_info).
    pub delivery_rate: u64,

    pub busy_time: u64,      // Time (usec) busy sending data
    pub rwnd_limited: u64,   // Time (usec) limited by receive window
    pub sndbuf_limited: u64, // Time (usec) limited by send buffer

    pub delivered: u32,
    pub delivered_ce: u32,

    pub bytes_sent: u64,    // RFC4898 tcpEStatsPerfHCDataOctetsOut
    pub bytes_retrans: u64, // RFC4898 tcpEStatsPerfOctetsRetrans
    pub dsack_dups: u32,    // RFC4898 tcpEStatsStackDSACKDups
    /// reordering events seen
    pub reord_seen: u32,

    /// Out-of-order packets received
    pub rcv_ooopack: u32,
    /// peer's advertised receive window after scaling (bytes)
    pub snd_wnd: u32,
}

impl<T: AsRef<[u8]>> Parseable<TcpInfoBuffer<T>> for TcpInfo {
    fn parse(buf: &TcpInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            state: buf.state(),
            ca_state: buf.congestion_avoidance_state(),
            retransmits: buf.retransmits(),
            probes: buf.probes(),
            backoff: buf.backoff(),
            options: buf.options(),
            wscale: buf.wscale(),
            delivery_rate_app_limited: buf.delivery_rate_app_limited(),
            rto: buf.rto(),
            ato: buf.ato(),
            snd_mss: buf.snd_mss(),
            rcv_mss: buf.rcv_mss(),
            unacked: buf.unacked(),
            sacked: buf.sacked(),
            lost: buf.lost(),
            retrans: buf.retrans(),
            fackets: buf.fackets(),
            last_data_sent: buf.last_data_sent(),
            last_ack_sent: buf.last_ack_sent(),
            last_data_recv: buf.last_data_recv(),
            last_ack_recv: buf.last_ack_recv(),
            pmtu: buf.pmtu(),
            rcv_ssthresh: buf.rcv_ssthresh(),
            rtt: buf.rtt(),
            rttvar: buf.rttvar(),
            snd_ssthresh: buf.snd_ssthresh(),
            snd_cwnd: buf.snd_cwnd(),
            advmss: buf.advmss(),
            reordering: buf.reordering(),
            rcv_rtt: buf.rcv_rtt(),
            rcv_space: buf.rcv_space(),
            total_retrans: buf.total_retrans(),
            pacing_rate: buf.pacing_rate(),
            max_pacing_rate: buf.max_pacing_rate(),
            bytes_acked: buf.bytes_acked(),
            bytes_received: buf.bytes_received(),
            segs_out: buf.segs_out(),
            segs_in: buf.segs_in(),
            notsent_bytes: buf.notsent_bytes(),
            min_rtt: buf.min_rtt(),
            data_segs_in: buf.data_segs_in(),
            data_segs_out: buf.data_segs_out(),
            delivery_rate: buf.delivery_rate(),
            busy_time: buf.busy_time(),
            rwnd_limited: buf.rwnd_limited(),
            sndbuf_limited: buf.sndbuf_limited(),
            delivered: buf.delivered(),
            delivered_ce: buf.delivered_ce(),
            bytes_sent: buf.bytes_sent(),
            bytes_retrans: buf.bytes_retrans(),
            dsack_dups: buf.dsack_dups(),
            reord_seen: buf.reord_seen(),
            rcv_ooopack: buf.rcv_ooopack(),
            snd_wnd: buf.snd_wnd(),
        })
    }
}

impl Emitable for TcpInfo {
    fn buffer_len(&self) -> usize {
        TCP_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = TcpInfoBuffer::new(buf);
        buf.set_state(self.state);
        buf.set_congestion_avoidance_state(self.ca_state);
        buf.set_retransmits(self.retransmits);
        buf.set_probes(self.probes);
        buf.set_backoff(self.backoff);
        buf.set_options(self.options);
        buf.set_wscale(self.wscale);
        buf.set_delivery_rate_app_limited(self.delivery_rate_app_limited);
        buf.set_rto(self.rto);
        buf.set_ato(self.ato);
        buf.set_snd_mss(self.snd_mss);
        buf.set_rcv_mss(self.rcv_mss);
        buf.set_unacked(self.unacked);
        buf.set_sacked(self.sacked);
        buf.set_lost(self.lost);
        buf.set_retrans(self.retrans);
        buf.set_fackets(self.fackets);
        buf.set_last_data_sent(self.last_data_sent);
        buf.set_last_ack_sent(self.last_ack_sent);
        buf.set_last_data_recv(self.last_data_recv);
        buf.set_last_ack_recv(self.last_ack_recv);
        buf.set_pmtu(self.pmtu);
        buf.set_rcv_ssthresh(self.rcv_ssthresh);
        buf.set_rtt(self.rtt);
        buf.set_rttvar(self.rttvar);
        buf.set_snd_ssthresh(self.snd_ssthresh);
        buf.set_snd_cwnd(self.snd_cwnd);
        buf.set_advmss(self.advmss);
        buf.set_reordering(self.reordering);
        buf.set_rcv_rtt(self.rcv_rtt);
        buf.set_rcv_space(self.rcv_space);
        buf.set_total_retrans(self.total_retrans);
        buf.set_pacing_rate(self.pacing_rate);
        buf.set_max_pacing_rate(self.max_pacing_rate);
        buf.set_bytes_acked(self.bytes_acked);
        buf.set_bytes_received(self.bytes_received);
        buf.set_segs_out(self.segs_out);
        buf.set_segs_in(self.segs_in);
        buf.set_notsent_bytes(self.notsent_bytes);
        buf.set_min_rtt(self.min_rtt);
        buf.set_data_segs_in(self.data_segs_in);
        buf.set_data_segs_out(self.data_segs_out);
        buf.set_delivery_rate(self.delivery_rate);
        buf.set_busy_time(self.busy_time);
        buf.set_rwnd_limited(self.rwnd_limited);
        buf.set_sndbuf_limited(self.sndbuf_limited);
        buf.set_delivered(self.delivered);
        buf.set_delivered_ce(self.delivered_ce);
        buf.set_bytes_sent(self.bytes_sent);
        buf.set_bytes_retrans(self.bytes_retrans);
        buf.set_dsack_dups(self.dsack_dups);
        buf.set_reord_seen(self.reord_seen);
        buf.set_rcv_ooopack(self.rcv_ooopack);
        buf.set_snd_wnd(self.snd_wnd);
    }
}
