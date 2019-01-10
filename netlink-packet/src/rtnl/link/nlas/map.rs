use byteorder::{ByteOrder, NativeEndian};

use crate::{DecodeError, Emitable, Field, Index, Parseable};

const MEMORY_START: Field = 0..8;
const MEMORY_END: Field = 8..16;
const BASE_ADDRESS: Field = 16..24;
const IRQ: Field = 24..26;
const DMA: Index = 26;
const PORT: Index = 27;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LinkMap {
    pub memory_start: u64,
    pub memory_end: u64,
    pub base_address: u64,
    pub irq: u16,
    pub dma: u8,
    pub port: u8,
}

pub const LINK_MAP_LEN: usize = PORT + 1;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkMapBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LinkMapBuffer<T> {
    pub fn new(buffer: T) -> LinkMapBuffer<T> {
        LinkMapBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<LinkMapBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < LINK_MAP_LEN {
            return Err(format!(
                "invalid LinkMapBuffer buffer: length is {} instead of {}",
                len, LINK_MAP_LEN
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn memory_start(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[MEMORY_START])
    }

    pub fn memory_end(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[MEMORY_END])
    }

    pub fn base_address(&self) -> u64 {
        NativeEndian::read_u64(&self.buffer.as_ref()[BASE_ADDRESS])
    }

    pub fn irq(&self) -> u16 {
        NativeEndian::read_u16(&self.buffer.as_ref()[IRQ])
    }

    pub fn dma(&self) -> u8 {
        self.buffer.as_ref()[DMA]
    }

    pub fn port(&self) -> u8 {
        self.buffer.as_ref()[PORT]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkMapBuffer<T> {
    pub fn set_memory_start(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[MEMORY_START], value.into())
    }

    pub fn set_memory_end(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[MEMORY_END], value.into())
    }

    pub fn set_base_address(&mut self, value: u64) {
        NativeEndian::write_u64(&mut self.buffer.as_mut()[BASE_ADDRESS], value.into())
    }

    pub fn set_irq(&mut self, value: u16) {
        NativeEndian::write_u16(&mut self.buffer.as_mut()[IRQ], value.into())
    }

    pub fn set_dma(&mut self, value: u8) {
        self.buffer.as_mut()[DMA] = value;
    }

    pub fn set_port(&mut self, value: u8) {
        self.buffer.as_mut()[PORT] = value
    }
}

impl<T: AsRef<[u8]>> Parseable<LinkMap> for LinkMapBuffer<T> {
    fn parse(&self) -> Result<LinkMap, DecodeError> {
        self.check_buffer_length()?;
        Ok(LinkMap {
            memory_start: self.memory_start(),
            memory_end: self.memory_end(),
            base_address: self.base_address(),
            irq: self.irq(),
            dma: self.dma(),
            port: self.port(),
        })
    }
}

impl Emitable for LinkMap {
    fn buffer_len(&self) -> usize {
        LINK_MAP_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = LinkMapBuffer::new(buffer);
        buffer.set_memory_start(self.memory_start);
        buffer.set_memory_end(self.memory_end);
        buffer.set_base_address(self.base_address);
        buffer.set_irq(self.irq);
        buffer.set_dma(self.dma);
        buffer.set_port(self.port);
    }
}
