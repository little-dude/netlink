use byteorder::{ByteOrder, NativeEndian};

use crate::{nlas, tc::constants::*};

pub const KIND: &str = "bpf";

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    Unspec(Vec<u8>),
    ClassId(u32),
    Fd(i32),
    Name(String),
    Flags(i32),
    Id(i32),
    Tag(String),
}

impl nlas::Nla for Nla {
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match self {
            Unspec(b) => b.len(),
            Fd(_) | Flags(_) | Id(_) => 4,
            ClassId(_) => 4,
            Name(s) | Tag(s) => s.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match self {
            Unspec(_) => TCA_BPF_UNSPEC,
            ClassId(_) => TCA_BPF_CLASSID,
            Fd(_) => TCA_BPF_FD,
            Name(_) => TCA_BPF_NAME,
            Flags(_) => TCA_BPF_FLAGS,
            Id(_) => TCA_BPF_ID,
            Tag(_) => TCA_BPF_TAG,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match self {
            Unspec(b) => buffer.copy_from_slice(b.as_slice()),
            ClassId(b) => NativeEndian::write_u32(buffer, *b),
            Fd(b) | Flags(b) | Id(b) => NativeEndian::write_i32(buffer, *b),
            Name(s) | Tag(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
        }
    }
}
