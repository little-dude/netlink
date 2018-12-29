use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use utils::{parse_string, parse_u32};
use {DecodeError, DefaultNla, Nla, NlaBuffer, Parseable};

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
    #[rustfmt::skip]
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

    #[rustfmt::skip]
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

            CacheInfo(ref cacheinfo) => cacheinfo.to_bytes(buffer).expect("check the buffer length before calling emit_value()!"),

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
    fn parse(&self) -> Result<AddressNla, DecodeError> {
        use self::AddressNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            IFA_UNSPEC => Unspec(payload.to_vec()),
            IFA_ADDRESS => Address(payload.to_vec()),
            IFA_LOCAL => Local(payload.to_vec()),
            IFA_LABEL => Label(parse_string(payload).context("invalid IFA_LABEL value")?),
            IFA_BROADCAST => Broadcast(payload.to_vec()),
            IFA_ANYCAST => Anycast(payload.to_vec()),
            IFA_CACHEINFO => CacheInfo(
                AddressCacheInfo::from_bytes(payload).context("invalid IFA_CACHEINFO value")?,
            ),
            IFA_MULTICAST => Multicast(payload.to_vec()),
            IFA_FLAGS => Flags(parse_u32(payload).context("invalid IFA_FLAGS value")?),
            kind => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context(format!("unknown NLA type {}", kind))?,
            ),
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

const ADDRESSS_CACHE_INFO_LEN: usize = 4 * 4;

impl AddressCacheInfo {
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < ADDRESSS_CACHE_INFO_LEN {
            return Err(DecodeError::from(format!(
                "IFA_CACHEINFO is {} bytes, buffer is only {} bytes: {:#x?}",
                ADDRESSS_CACHE_INFO_LEN,
                buf.len(),
                buf
            )));
        }
        Ok(AddressCacheInfo {
            ifa_preferred: NativeEndian::read_i32(&buf[0..4]),
            ifa_valid: NativeEndian::read_i32(&buf[4..8]),
            cstamp: NativeEndian::read_i32(&buf[8..12]),
            tstamp: NativeEndian::read_i32(&buf[12..16]),
        })
    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if buf.len() < ADDRESSS_CACHE_INFO_LEN {
            return Err(DecodeError::from(format!(
                "buffer is only {} long, but IFA_CACHEINFO is {} bytes",
                buf.len(),
                ADDRESSS_CACHE_INFO_LEN
            )));
        }
        NativeEndian::write_i32(&mut buf[0..4], self.ifa_preferred);
        NativeEndian::write_i32(&mut buf[4..8], self.ifa_valid);
        NativeEndian::write_i32(&mut buf[8..12], self.cstamp);
        NativeEndian::write_i32(&mut buf[12..16], self.tstamp);
        Ok(())
    }
}
