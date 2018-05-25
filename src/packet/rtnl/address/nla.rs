use byteorder::{ByteOrder, NativeEndian};
use std::mem::size_of;

use constants;

use packet::common::nla::{parse_string, parse_u32, DefaultNla, NativeNla, Nla, NlaBuffer};
use packet::common::{Parseable, Result};

use super::cacheinfo;

pub const IFA_F_SECONDARY: u32 = constants::IFA_F_SECONDARY as u32;
pub const IFA_F_TEMPORARY: u32 = constants::IFA_F_TEMPORARY as u32;
pub const IFA_F_NODAD: u32 = constants::IFA_F_NODAD as u32;
pub const IFA_F_OPTIMISTIC: u32 = constants::IFA_F_OPTIMISTIC as u32;
pub const IFA_F_DADFAILED: u32 = constants::IFA_F_DADFAILED as u32;
pub const IFA_F_HOMEADDRESS: u32 = constants::IFA_F_HOMEADDRESS as u32;
pub const IFA_F_DEPRECATED: u32 = constants::IFA_F_DEPRECATED as u32;
pub const IFA_F_TENTATIVE: u32 = constants::IFA_F_TENTATIVE as u32;
pub const IFA_F_PERMANENT: u32 = constants::IFA_F_PERMANENT as u32;
pub const IFA_F_MANAGETEMPADDR: u32 = constants::IFA_F_MANAGETEMPADDR as u32;
pub const IFA_F_NOPREFIXROUTE: u32 = constants::IFA_F_NOPREFIXROUTE as u32;
pub const IFA_F_MCAUTOJOIN: u32 = constants::IFA_F_MCAUTOJOIN as u32;
pub const IFA_F_STABLE_PRIVACY: u32 = constants::IFA_F_STABLE_PRIVACY as u32;

pub const IFA_UNSPEC: u16 = constants::IFA_UNSPEC as u16;
pub const IFA_ADDRESS: u16 = constants::IFA_ADDRESS as u16;
pub const IFA_LOCAL: u16 = constants::IFA_LOCAL as u16;
pub const IFA_LABEL: u16 = constants::IFA_LABEL as u16;
pub const IFA_BROADCAST: u16 = constants::IFA_BROADCAST as u16;
pub const IFA_ANYCAST: u16 = constants::IFA_ANYCAST as u16;
pub const IFA_CACHEINFO: u16 = constants::IFA_CACHEINFO as u16;
pub const IFA_MULTICAST: u16 = constants::IFA_MULTICAST as u16;
pub const IFA_FLAGS: u16 = constants::IFA_FLAGS as u16;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AddressNla {
    Unspec(Vec<u8>),
    Address(Vec<u8>),
    Local(Vec<u8>),
    Label(String),
    Broadcast(Vec<u8>),
    Anycast(Vec<u8>),
    CacheInfo(cacheinfo::CacheInfo),
    Multicast(Vec<u8>),
    Flags(u32),
    Other(DefaultNla),
}

impl Nla for AddressNla {
    #[allow(unused_attributes)]
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
            CacheInfo(_) => size_of::<cacheinfo::CacheInfo>(),

            // Defaults
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[allow(unused_attributes)]
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
                buffer.copy_from_slice(string.as_bytes());
                buffer[string.as_bytes().len()] = 0;
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
            IFA_CACHEINFO => CacheInfo(cacheinfo::CacheInfo::from_bytes(payload)?),
            IFA_MULTICAST => Multicast(payload.to_vec()),
            IFA_FLAGS => Flags(parse_u32(payload)?),
            _ => Other(<Self as Parseable<DefaultNla>>::parse(self)?),
        })
    }
}
