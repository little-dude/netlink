use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LinkStats {
    /// total packets received
    pub rx_packets: u32,
    /// total packets transmitted
    pub tx_packets: u32,
    /// total bytes received
    pub rx_bytes: u32,
    /// total bytes transmitted
    pub tx_bytes: u32,
    /// bad packets received
    pub rx_errors: u32,
    /// packet transmit problems
    pub tx_errors: u32,
    /// no space in linux buffers
    pub rx_dropped: u32,
    /// no space available in linux
    pub tx_dropped: u32,
    /// multicast packets received
    pub multicast: u32,
    pub collisions: u32,

    // detailed rx_errors
    pub rx_length_errors: u32,
    /// receiver ring buff overflow
    pub rx_over_errors: u32,
    /// received packets with crc error
    pub rx_crc_errors: u32,
    /// received frame alignment errors
    pub rx_frame_errors: u32,
    /// recv'r fifo overrun
    pub rx_fifo_errors: u32,
    /// receiver missed packet
    pub rx_missed_errors: u32,

    // detailed tx_errors
    pub tx_aborted_errors: u32,
    pub tx_carrier_errors: u32,
    pub tx_fifo_errors: u32,
    pub tx_heartbeat_errors: u32,
    pub tx_window_errors: u32,

    // for cslip etc
    pub rx_compressed: u32,
    pub tx_compressed: u32,

    /// dropped, no handler found
    pub rx_nohandler: u32,
}

const RX_PACKETS: Field = 0..4;
const TX_PACKETS: Field = 4..8;
const RX_BYTES: Field = 8..12;
const TX_BYTES: Field = 12..16;
const RX_ERRORS: Field = 16..20;
const TX_ERRORS: Field = 20..24;
const RX_DROPPED: Field = 24..28;
const TX_DROPPED: Field = 28..32;
const MULTICAST: Field = 32..36;
const COLLISIONS: Field = 36..40;
const RX_LENGTH_ERRORS: Field = 40..44;
const RX_OVER_ERRORS: Field = 44..48;
const RX_CRC_ERRORS: Field = 48..52;
const RX_FRAME_ERRORS: Field = 52..56;
const RX_FIFO_ERRORS: Field = 56..60;
const RX_MISSED_ERRORS: Field = 60..64;
const TX_ABORTED_ERRORS: Field = 64..68;
const TX_CARRIER_ERRORS: Field = 68..72;
const TX_FIFO_ERRORS: Field = 72..76;
const TX_HEARTBEAT_ERRORS: Field = 76..80;
const TX_WINDOW_ERRORS: Field = 80..84;
const RX_COMPRESSED: Field = 84..88;
const TX_COMPRESSED: Field = 88..92;
const RX_NOHANDLER: Field = 92..96;

pub const LINK_STATS_LEN: usize = RX_NOHANDLER.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkStatsBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkStatsBuffer<T> {
    pub fn new(buffer: T) -> LinkStatsBuffer<T> {
        LinkStatsBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<LinkStatsBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_STATS_LEN {
            return Err(format!(
                "invalid LinkStatsBuffer buffer: length is {} instead of {}",
                len, LINK_STATS_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn rx_packets(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_PACKETS])
    }

    pub fn tx_packets(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_PACKETS])
    }

    pub fn rx_bytes(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_BYTES])
    }

    pub fn tx_bytes(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_BYTES])
    }

    pub fn rx_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_ERRORS])
    }

    pub fn tx_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_ERRORS])
    }

    pub fn rx_dropped(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_DROPPED])
    }

    pub fn tx_dropped(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_DROPPED])
    }

    pub fn multicast(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[MULTICAST])
    }

    pub fn collisions(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[COLLISIONS])
    }

    pub fn rx_length_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_LENGTH_ERRORS])
    }

    pub fn rx_over_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_OVER_ERRORS])
    }

    pub fn rx_crc_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_CRC_ERRORS])
    }

    pub fn rx_frame_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_FRAME_ERRORS])
    }

    pub fn rx_fifo_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_FIFO_ERRORS])
    }

    pub fn rx_missed_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_MISSED_ERRORS])
    }

    pub fn tx_aborted_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_ABORTED_ERRORS])
    }

    pub fn tx_carrier_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_CARRIER_ERRORS])
    }

    pub fn tx_fifo_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_FIFO_ERRORS])
    }

    pub fn tx_heartbeat_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_HEARTBEAT_ERRORS])
    }

    pub fn tx_window_errors(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_WINDOW_ERRORS])
    }

    pub fn rx_compressed(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_COMPRESSED])
    }

    pub fn tx_compressed(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[TX_COMPRESSED])
    }

    pub fn rx_nohandler(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RX_NOHANDLER])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkStatsBuffer<T> {
    pub fn set_rx_packets(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_PACKETS], value)
    }

    pub fn set_tx_packets(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_PACKETS], value)
    }

    pub fn set_rx_bytes(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_BYTES], value)
    }

    pub fn set_tx_bytes(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_BYTES], value)
    }

    pub fn set_rx_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_ERRORS], value)
    }

    pub fn set_tx_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_ERRORS], value)
    }

    pub fn set_rx_dropped(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_DROPPED], value)
    }

    pub fn set_tx_dropped(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_DROPPED], value)
    }

    pub fn set_multicast(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[MULTICAST], value)
    }

    pub fn set_collisions(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[COLLISIONS], value)
    }

    pub fn set_rx_length_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_LENGTH_ERRORS], value)
    }

    pub fn set_rx_over_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_OVER_ERRORS], value)
    }

    pub fn set_rx_crc_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_CRC_ERRORS], value)
    }

    pub fn set_rx_frame_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_FRAME_ERRORS], value)
    }

    pub fn set_rx_fifo_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_FIFO_ERRORS], value)
    }

    pub fn set_rx_missed_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_MISSED_ERRORS], value)
    }

    pub fn set_tx_aborted_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_ABORTED_ERRORS], value)
    }

    pub fn set_tx_carrier_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_CARRIER_ERRORS], value)
    }

    pub fn set_tx_fifo_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_FIFO_ERRORS], value)
    }

    pub fn set_tx_heartbeat_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_HEARTBEAT_ERRORS], value)
    }

    pub fn set_tx_window_errors(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_WINDOW_ERRORS], value)
    }

    pub fn set_rx_compressed(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_COMPRESSED], value)
    }

    pub fn set_tx_compressed(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[TX_COMPRESSED], value)
    }

    pub fn set_rx_nohandler(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RX_NOHANDLER], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkStats> for LinkStatsBuffer<T> {
    fn parse(&self) -> Result<LinkStats, DecodeError> {
        self.check_buffer_length()?;
        Ok(LinkStats {
            rx_packets: self.rx_packets(),
            tx_packets: self.tx_packets(),
            rx_bytes: self.rx_bytes(),
            tx_bytes: self.tx_bytes(),
            rx_errors: self.rx_errors(),
            tx_errors: self.tx_errors(),
            rx_dropped: self.rx_dropped(),
            tx_dropped: self.tx_dropped(),
            multicast: self.multicast(),
            collisions: self.collisions(),
            rx_length_errors: self.rx_length_errors(),
            rx_over_errors: self.rx_over_errors(),
            rx_crc_errors: self.rx_crc_errors(),
            rx_frame_errors: self.rx_frame_errors(),
            rx_fifo_errors: self.rx_fifo_errors(),
            rx_missed_errors: self.rx_missed_errors(),
            tx_aborted_errors: self.tx_aborted_errors(),
            tx_carrier_errors: self.tx_carrier_errors(),
            tx_fifo_errors: self.tx_fifo_errors(),
            tx_heartbeat_errors: self.tx_heartbeat_errors(),
            tx_window_errors: self.tx_window_errors(),
            rx_compressed: self.rx_compressed(),
            tx_compressed: self.tx_compressed(),
            rx_nohandler: self.rx_nohandler(),
        })
    }
}

impl Emitable for LinkStats {
    fn buffer_len(&self) -> usize {
        LINK_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkStatsBuffer::new(buffer);
        buffer.set_rx_packets(self.rx_packets);
        buffer.set_tx_packets(self.tx_packets);
        buffer.set_rx_bytes(self.rx_bytes);
        buffer.set_tx_bytes(self.tx_bytes);
        buffer.set_rx_errors(self.rx_errors);
        buffer.set_tx_errors(self.tx_errors);
        buffer.set_rx_dropped(self.rx_dropped);
        buffer.set_tx_dropped(self.tx_dropped);
        buffer.set_multicast(self.multicast);
        buffer.set_collisions(self.collisions);
        buffer.set_rx_length_errors(self.rx_length_errors);
        buffer.set_rx_over_errors(self.rx_over_errors);
        buffer.set_rx_crc_errors(self.rx_crc_errors);
        buffer.set_rx_frame_errors(self.rx_frame_errors);
        buffer.set_rx_fifo_errors(self.rx_fifo_errors);
        buffer.set_rx_missed_errors(self.rx_missed_errors);
        buffer.set_tx_aborted_errors(self.tx_aborted_errors);
        buffer.set_tx_carrier_errors(self.tx_carrier_errors);
        buffer.set_tx_fifo_errors(self.tx_fifo_errors);
        buffer.set_tx_heartbeat_errors(self.tx_heartbeat_errors);
        buffer.set_tx_window_errors(self.tx_window_errors);
        buffer.set_rx_compressed(self.rx_compressed);
        buffer.set_tx_compressed(self.tx_compressed);
        buffer.set_rx_nohandler(self.rx_nohandler);
    }
}
