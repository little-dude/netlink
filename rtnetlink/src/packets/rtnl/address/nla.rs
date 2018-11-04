use byteorder::{ByteOrder, NativeEndian};
use std::mem::size_of;

use utils::{parse_string, parse_u32};
use {DefaultNla, NativeNla, Nla, NlaBuffer, Parseable, Result};

use constants::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AddressNla {
    Unspec(Vec<u8>),
    Address(Vec<u8>),
    Local(Vec<u8>),
    Label(String),
    Broadcast(Vec<u8>),
    Anycast(Vec<u8>),
    CacheInfo(AddressCacheInfo),
    Multicast(Vec<u8>),
    Flags(u32),
    Other(DefaultNla),
}

impl Nla for AddressNla {
    #[cfg_attr(nightly, rustfmt::skip)]
    fn value_len(&self) -> usize {
        use self::AddressNla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Address(ref bytes)
                | Local(ref bytes)
                | Broadcast(ref bytes)
                | Anycast(ref bytes)
                | Multicast(ref bytes) => bytes.len(),

            // strings: +1 because we need to append a nul byte
            Label(ref string) => string.as_bytes().len() + 1,

            // u32
            Flags(_) => size_of::<u32>(),

            // Native
            CacheInfo(_) => size_of::<AddressCacheInfo>(),

            // Defaults
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::AddressNla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Address(ref bytes)
                | Local(ref bytes)
                | Broadcast(ref bytes)
                | Anycast(ref bytes)
                | Multicast(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            // String
            Label(ref string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }

            // u32
            Flags(ref value) => NativeEndian::write_u32(buffer, *value),

            // Native
            CacheInfo(ref cacheinfo) => cacheinfo.to_bytes(buffer),

            // Default
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::AddressNla::*;
        match *self {
            Unspec(_) => IFA_UNSPEC,
            Address(_) => IFA_ADDRESS,
            Local(_) => IFA_LOCAL,
            Label(_) => IFA_LABEL,
            Broadcast(_) => IFA_BROADCAST,
            Anycast(_) => IFA_ANYCAST,
            CacheInfo(_) => IFA_CACHEINFO,
            Multicast(_) => IFA_MULTICAST,
            Flags(_) => IFA_FLAGS,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<AddressNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<AddressNla> {
        use self::AddressNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFA_UNSPEC => Unspec(payload.to_vec()),
            IFA_ADDRESS => Address(payload.to_vec()),
            IFA_LOCAL => Local(payload.to_vec()),
            IFA_LABEL => Label(parse_string(payload)?),
            IFA_BROADCAST => Broadcast(payload.to_vec()),
            IFA_ANYCAST => Anycast(payload.to_vec()),
            IFA_CACHEINFO => CacheInfo(AddressCacheInfo::from_bytes(payload)?),
            IFA_MULTICAST => Multicast(payload.to_vec()),
            IFA_FLAGS => Flags(parse_u32(payload)?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AddressCacheInfo {
    pub ifa_preferred: i32,
    pub ifa_valid: i32,
    pub cstamp: i32,
    pub tstamp: i32,
}

impl NativeNla for AddressCacheInfo {}
