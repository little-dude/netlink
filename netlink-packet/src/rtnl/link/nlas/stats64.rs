use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Parseable};

const RX_PACKETS: Field = 0..8;
const TX_PACKETS: Field = 8..16;
const RX_BYTES: Field = 16..24;
const TX_BYTES: Field = 24..32;
const RX_ERRORS: Field = 32..40;
const TX_ERRORS: Field = 40..48;
const RX_DROPPED: Field = 48..56;
const TX_DROPPED: Field = 56..64;
const MULTICAST: Field = 64..72;
const COLLISIONS: Field = 72..80;
const RX_LENGTH_ERRORS: Field = 80..88;
const RX_OVER_ERRORS: Field = 88..96;
const RX_CRC_ERRORS: Field = 96..104;
const RX_FRAME_ERRORS: Field = 104..112;
const RX_FIFO_ERRORS: Field = 112..120;
const RX_MISSED_ERRORS: Field = 120..128;
const TX_ABORTED_ERRORS: Field = 128..136;
const TX_CARRIER_ERRORS: Field = 136..144;
const TX_FIFO_ERRORS: Field = 144..152;
const TX_HEARTBEAT_ERRORS: Field = 152..160;
const TX_WINDOW_ERRORS: Field = 160..168;
const RX_COMPRESSED: Field = 168..176;
const TX_COMPRESSED: Field = 176..184;
const RX_NOHANDLER: Field = 184..192;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LinkStats64 {
    /// total packets received
    pub rx_packets: u64,
    /// total packets transmitted
    pub tx_packets: u64,
    /// total bytes received
    pub rx_bytes: u64,
    /// total bytes transmitted
    pub tx_bytes: u64,
    /// bad packets received
    pub rx_errors: u64,
    /// packet transmit problems
    pub tx_errors: u64,
    /// no space in linux buffers
    pub rx_dropped: u64,
    /// no space available in linux
    pub tx_dropped: u64,
    /// multicast packets received
    pub multicast: u64,
    pub collisions: u64,

    // detailed rx_errors
    pub rx_length_errors: u64,
    /// receiver ring buff overflow
    pub rx_over_errors: u64,
    /// received packets with crc error
    pub rx_crc_errors: u64,
    /// received frame alignment errors
    pub rx_frame_errors: u64,
    /// recv'r fifo overrun
    pub rx_fifo_errors: u64,
    /// receiver missed packet
    pub rx_missed_errors: u64,

    // detailed tx_errors
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,

    // for cslip etc
    pub rx_compressed: u64,
    pub tx_compressed: u64,

    /// dropped, no handler found
    pub rx_nohandler: u64,
}

pub const LINK_STATS64_LEN: usize = RX_NOHANDLER.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkStats64Buffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkStats64Buffer<T> {
    pub fn new(buffer: T) -> LinkStats64Buffer<T> {
        LinkStats64Buffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<LinkStats64Buffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_STATS64_LEN {
            return Err(format!(
                "invalid LinkStats64Buffer buffer: length is {} instead of {}",
                len, LINK_STATS64_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn rx_packets(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_PACKETS])
    }

    pub fn tx_packets(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_PACKETS])
    }

    pub fn rx_bytes(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_BYTES])
    }

    pub fn tx_bytes(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_BYTES])
    }

    pub fn rx_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_ERRORS])
    }

    pub fn tx_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_ERRORS])
    }

    pub fn rx_dropped(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_DROPPED])
    }

    pub fn tx_dropped(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_DROPPED])
    }

    pub fn multicast(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[MULTICAST])
    }

    pub fn collisions(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[COLLISIONS])
    }

    pub fn rx_length_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_LENGTH_ERRORS])
    }

    pub fn rx_over_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_OVER_ERRORS])
    }

    pub fn rx_crc_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_CRC_ERRORS])
    }

    pub fn rx_frame_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_FRAME_ERRORS])
    }

    pub fn rx_fifo_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_FIFO_ERRORS])
    }

    pub fn rx_missed_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_MISSED_ERRORS])
    }

    pub fn tx_aborted_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_ABORTED_ERRORS])
    }

    pub fn tx_carrier_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_CARRIER_ERRORS])
    }

    pub fn tx_fifo_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_FIFO_ERRORS])
    }

    pub fn tx_heartbeat_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_HEARTBEAT_ERRORS])
    }

    pub fn tx_window_errors(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_WINDOW_ERRORS])
    }

    pub fn rx_compressed(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_COMPRESSED])
    }

    pub fn tx_compressed(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[TX_COMPRESSED])
    }

    pub fn rx_nohandler(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[RX_NOHANDLER])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkStats64Buffer<T> {
    pub fn set_rx_packets(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_PACKETS], value)
    }

    pub fn set_tx_packets(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_PACKETS], value)
    }

    pub fn set_rx_bytes(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_BYTES], value)
    }

    pub fn set_tx_bytes(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_BYTES], value)
    }

    pub fn set_rx_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_ERRORS], value)
    }

    pub fn set_tx_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_ERRORS], value)
    }

    pub fn set_rx_dropped(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_DROPPED], value)
    }

    pub fn set_tx_dropped(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_DROPPED], value)
    }

    pub fn set_multicast(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[MULTICAST], value)
    }

    pub fn set_collisions(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[COLLISIONS], value)
    }

    pub fn set_rx_length_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_LENGTH_ERRORS], value)
    }

    pub fn set_rx_over_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_OVER_ERRORS], value)
    }

    pub fn set_rx_crc_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_CRC_ERRORS], value)
    }

    pub fn set_rx_frame_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_FRAME_ERRORS], value)
    }

    pub fn set_rx_fifo_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_FIFO_ERRORS], value)
    }

    pub fn set_rx_missed_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_MISSED_ERRORS], value)
    }

    pub fn set_tx_aborted_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_ABORTED_ERRORS], value)
    }

    pub fn set_tx_carrier_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_CARRIER_ERRORS], value)
    }

    pub fn set_tx_fifo_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_FIFO_ERRORS], value)
    }

    pub fn set_tx_heartbeat_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_HEARTBEAT_ERRORS], value)
    }

    pub fn set_tx_window_errors(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_WINDOW_ERRORS], value)
    }

    pub fn set_rx_compressed(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_COMPRESSED], value)
    }

    pub fn set_tx_compressed(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[TX_COMPRESSED], value)
    }

    pub fn set_rx_nohandler(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[RX_NOHANDLER], value)
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkStats64> for LinkStats64Buffer<T> {
    fn parse(&self) -> Result<LinkStats64, DecodeError> {
        Ok(LinkStats64 {
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

impl Emitable for LinkStats64 {
    fn buffer_len(&self) -> usize {
        LINK_STATS64_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkStats64Buffer::new(buffer);
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
