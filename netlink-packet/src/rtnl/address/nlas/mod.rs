mod cache_info;
pub use self::cache_info::*;

use std::mem::size_of;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::utils::{parse_string, parse_u32};
use crate::{DecodeError, DefaultNla, Emitable, Nla, NlaBuffer, Parseable};

use crate::constants::*;

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
            CacheInfo(_) => ADDRESSS_CACHE_INFO_LEN,

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

            CacheInfo(ref cacheinfo) => cacheinfo.emit(buffer),

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
                AddressCacheInfoBuffer::new_checked(payload)
                    .context("invalid IFA_CACHEINFO value")?
                    .parse()
                    .context("invalid IFA_CACHEINFO value")?,
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
