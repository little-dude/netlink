use packet::attribute::NativeAttribute;

// FIXME: should this be repr(packed) instead?
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Stats<T> {
    /// total packets received
    rx_packets: T,
    /// total packets transmitted
    tx_packets: T,
    /// total bytes received
    rx_bytes: T,
    /// total bytes transmitted
    tx_bytes: T,
    /// bad packets received
    rx_errors: T,
    /// packet transmit problems
    tx_errors: T,
    /// no space in linux buffers
    rx_dropped: T,
    /// no space available in linux
    tx_dropped: T,
    /// multicast packets received
    multicast: T,
    collisions: T,

    // detailed rx_errors
    rx_length_errors: T,
    /// receiver ring buff overflow
    rx_over_errors: T,
    /// received packets with crc error
    rx_crc_errors: T,
    /// received frame alignment errors
    rx_frame_errors: T,
    /// recv'r fifo overrun
    rx_fifo_errors: T,
    /// receiver missed packet
    rx_missed_errors: T,

    // detailed tx_errors
    tx_aborted_errors: T,
    tx_carrier_errors: T,
    tx_fifo_errors: T,
    tx_heartbeat_errors: T,
    tx_window_errors: T,

    // for cslip etc
    rx_compressed: T,
    tx_compressed: T,

    /// dropped, no handler found
    rx_nohandler: T,
}

impl NativeAttribute for Stats<u32> {}
impl NativeAttribute for Stats<u64> {}

pub type Stats32 = Stats<u32>;
pub type Stats64 = Stats<u64>;
