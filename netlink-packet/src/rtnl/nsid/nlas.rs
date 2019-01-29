use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::constants::*;
use crate::utils::parse_u32;
use crate::{DecodeError, DefaultNla, Nla, NlaBuffer, Parseable};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NsIdNla {
    Unspec(Vec<u8>),
    NsId(u32),
    Pid(u32),
    Fd(u32),
    Other(DefaultNla),
}

impl Nla for NsIdNla {
    fn value_len(&self) -> usize {
        use self::NsIdNla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            NsId(_) | Pid(_) | Fd(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::NsIdNla::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            NsId(ref value) | Pid(ref value) | Fd(ref value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::NsIdNla::*;
        match *self {
            Unspec(_) => NETNSA_NONE,
            NsId(_) => NETNSA_NSID,
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
            NETNSA_NSID => NsId(parse_u32(payload).context("invalid NETNSA_NSID")?),
            NETNSA_PID => Pid(parse_u32(payload).context("invalid NETNSA_PID")?),
            NETNSA_FD => Pid(parse_u32(payload).context("invalid NETNSA_FD")?),
            kind => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context(format!("unknown NLA type {}", kind))?,
            ),
        })
    }
}
