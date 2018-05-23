use packet::utils::nla::NativeNla;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CacheInfo {
    pub ifa_preferred: i32,
    pub ifa_valid: i32,
    pub cstamp: i32,
    pub tstamp: i32,
}

impl NativeNla for CacheInfo {}
