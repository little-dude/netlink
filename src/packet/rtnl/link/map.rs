use packet::common::nla::NativeNla;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Map {
    pub memory_start: u64,
    pub memory_end: u64,
    pub base_address: u64,
    pub irq: u16,
    pub dma: u8,
    pub port: u8,
}

impl NativeNla for Map {}
