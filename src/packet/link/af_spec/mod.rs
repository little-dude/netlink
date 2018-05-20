// IFLA_AF_SPEC
//
// Contains nested attributes for address family specific attributes. Each address family may
// create a attribute with the address family number as type and create its own attribute structure
// in it.
//
// [IFLA_AF_SPEC] = {
//     [AF_INET] = {
//         [IFLA_INET_CONF] = ...,
//     },
//     [AF_INET6] = {
//         [IFLA_INET6_FLAGS] = ...,
//         [IFLA_INET6_CONF] = ...,
//     }
//     [AF_XXX] = { ... },
//     ...
// }

mod constants;
mod inet;
mod inet6;

#[cfg(test)]
mod tests;

// Just re-export everything. We don't want to export the inner structure of this module
pub use self::constants::*;
pub use self::inet::*;
pub use self::inet6::*;

use packet::attribute::{emit_attributes, Attribute, AttributesIterator, Buffer, DefaultAttribute};
use packet::Result;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AfSpec {
    Unspec(Vec<u8>),
    Unix(Vec<u8>),
    Ax25(Vec<u8>),
    Ipx(Vec<u8>),
    AppleTalk(Vec<u8>),
    Netrom(Vec<u8>),
    Bridge(Vec<u8>),
    AtmPvc(Vec<u8>),
    X25(Vec<u8>),
    Inet6(Vec<AfInet6>),
    Inet(Vec<AfInet>),
    Other(DefaultAttribute),
}

impl Attribute for AfSpec {
    #[allow(unused_attributes)]
    #[rustfmt_skip]
    fn length(&self) -> usize {
        use self::AfSpec::*;
        match *self {
            Unspec(ref bytes)
                | Unix(ref bytes)
                | Ax25(ref bytes)
                | Ipx(ref bytes)
                | AppleTalk(ref bytes)
                | Netrom(ref bytes)
                | Bridge(ref bytes)
                | AtmPvc(ref bytes)
                | X25(ref bytes) => bytes.len(),
            Inet6(ref af_inet6) => af_inet6.iter().fold(0, |sum, attr| sum + 4 + attr.length()),
            Inet(ref af_inet) =>  af_inet.iter().fold(0, |sum, attr| sum + 4 + attr.length()),
            Other(ref attr) => attr.length(),
        }
    }

    #[allow(unused_attributes)]
    #[rustfmt_skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::AfSpec::*;
        match *self {
            Unspec(ref bytes)
                | Unix(ref bytes)
                | Ax25(ref bytes)
                | Ipx(ref bytes)
                | AppleTalk(ref bytes)
                | Netrom(ref bytes)
                | Bridge(ref bytes)
                | AtmPvc(ref bytes)
                | X25(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            AfSpec::Inet6(ref attrs) => {
                // This may panic if:
                //     - attributes are malformed (mitigated by rust's type system guarantees)
                //     - the buffer is not big enough. But normally, before emit_value is called,
                //       the length is checked, so this should not be a problem.
                let _ = emit_attributes(buffer, attrs.iter())
                    .expect("failed to emit attributes");
            }
            AfSpec::Inet(ref attrs) => {
                // See above for possible failures
                let _ = emit_attributes(buffer, attrs.iter())
                    .expect("failed to emit attributes");
            }
            AfSpec::Other(ref attr)  => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::AfSpec::*;
        match *self {
            Inet(_) => AF_INET,
            Unspec(_) => AF_UNSPEC,
            Unix(_) => AF_UNIX,
            Ax25(_) => AF_AX25,
            Ipx(_) => AF_IPX,
            AppleTalk(_) => AF_APPLETALK,
            Netrom(_) => AF_NETROM,
            Bridge(_) => AF_BRIDGE,
            AtmPvc(_) => AF_ATMPVC,
            X25(_) => AF_X25,
            Inet6(_) => AF_INET6,
            Other(ref attr) => attr.kind(),
        }
    }

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(buffer: Buffer<&'a T>) -> Result<Self> {
        use self::AfSpec::*;
        let payload = buffer.value();
        Ok(match buffer.kind() {
            AF_UNSPEC => Unspec(payload.to_vec()),
            AF_INET => {
                let mut attributes = vec![];
                for attr in AttributesIterator::new(payload) {
                    attributes.push(AfInet::parse(attr?)?)
                }
                Inet(attributes)
            }
            AF_INET6 => {
                let mut attributes = vec![];
                for attr in AttributesIterator::new(payload) {
                    attributes.push(AfInet6::parse(attr?)?)
                }
                Inet6(attributes)
            }
            AF_UNIX => Unix(payload.to_vec()),
            AF_AX25 => Ax25(payload.to_vec()),
            AF_IPX => Ipx(payload.to_vec()),
            AF_APPLETALK => AppleTalk(payload.to_vec()),
            AF_NETROM => Netrom(payload.to_vec()),
            AF_BRIDGE => Bridge(payload.to_vec()),
            AF_ATMPVC => AtmPvc(payload.to_vec()),
            AF_X25 => X25(payload.to_vec()),
            _ => AfSpec::Other(DefaultAttribute::parse(buffer)?),
        })
    }
}
