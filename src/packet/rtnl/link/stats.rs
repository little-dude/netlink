use packet::utils::nla::NativeNla;

// FIXME: should this be repr(packed) instead?
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Stats<T> {
    /// total packets received
    pub rx_packets: T,
    /// total packets transmitted
    pub tx_packets: T,
    /// total bytes received
    pub rx_bytes: T,
    /// total bytes transmitted
    pub tx_bytes: T,
    /// bad packets received
    pub rx_errors: T,
    /// packet transmit problems
    pub tx_errors: T,
    /// no space in linux buffers
    pub rx_dropped: T,
    /// no space available in linux
    pub tx_dropped: T,
    /// multicast packets received
    pub multicast: T,
    pub collisions: T,

    // detailed rx_errors
    pub rx_length_errors: T,
    /// receiver ring buff overflow
    pub rx_over_errors: T,
    /// received packets with crc error
    pub rx_crc_errors: T,
    /// received frame alignment errors
    pub rx_frame_errors: T,
    /// recv'r fifo overrun
    pub rx_fifo_errors: T,
    /// receiver missed packet
    pub rx_missed_errors: T,

    // detailed tx_errors
    pub tx_aborted_errors: T,
    pub tx_carrier_errors: T,
    pub tx_fifo_errors: T,
    pub tx_heartbeat_errors: T,
    pub tx_window_errors: T,

    // for cslip etc
    pub rx_compressed: T,
    pub tx_compressed: T,

    /// dropped, no handler found
    pub rx_nohandler: T,
}

impl NativeNla for Stats<u32> {}
impl NativeNla for Stats<u64> {}

pub type Stats32 = Stats<u32>;
pub type Stats64 = Stats<u64>;
