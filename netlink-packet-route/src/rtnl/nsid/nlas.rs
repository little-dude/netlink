use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{
    rtnl::{
        nla::{DefaultNla, Nla, NlaBuffer},
        traits::Parseable,
        utils::{parse_i32, parse_u32},
    },
    DecodeError,
};

pub const NETNSA_NONE: u16 = 0;
pub const NETNSA_NSID: u16 = 1;
pub const NETNSA_PID: u16 = 2;
pub const NETNSA_FD: u16 = 3;
pub const NETNSA_NSID_NOT_ASSIGNED: i32 = -1;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NsIdNla {
    Unspec(Vec<u8>),
    Id(i32),
    Pid(u32),
    Fd(u32),
    Other(DefaultNla),
}

impl Nla for NsIdNla {
    fn value_len(&self) -> usize {
        use self::NsIdNla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            Id(_) | Pid(_) | Fd(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::NsIdNla::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Fd(ref value) | Pid(ref value) => NativeEndian::write_u32(buffer, *value),
            Id(ref value) => NativeEndian::write_i32(buffer, *value),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::NsIdNla::*;
        match *self {
            Unspec(_) => NETNSA_NONE,
            Id(_) => NETNSA_NSID,
            Pid(_) => NETNSA_PID,
            Fd(_) => NETNSA_FD,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NsIdNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<NsIdNla, DecodeError> {
        use self::NsIdNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            NETNSA_NONE => Unspec(payload.to_vec()),
            NETNSA_NSID => Id(parse_i32(payload).context("invalid NETNSA_NSID")?),
            NETNSA_PID => Pid(parse_u32(payload).context("invalid NETNSA_PID")?),
            NETNSA_FD => Fd(parse_u32(payload).context("invalid NETNSA_FD")?),
            kind => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context(format!("unknown NLA type {}", kind))?,
            ),
        })
    }
}
