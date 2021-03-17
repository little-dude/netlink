use crate::constants::*;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla},
    Emitable,
};
use std::mem::size_of_val;

mod mcast;
mod op;
mod policy;

pub use mcast::McastGrpAttrs;
pub use op::OpAttrs;
pub use policy::PolicyAttrs;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenlCtrlAttrs {
    Unspec(Vec<u8>),
    FamilyId(u16),
    FamilyName(String),
    Version(u32),
    HdrSize(u32),
    MaxAttr(u32),
    Ops(Vec<OpAttrs>),
    McastGroups(Vec<McastGrpAttrs>),
    Policy(Vec<u8>),
    OpPolicy(Vec<u8>),
    Op(u32),
    Other(DefaultNla),
}

impl Nla for GenlCtrlAttrs {
    fn value_len(&self) -> usize {
        use GenlCtrlAttrs::*;
        match self {
            Unspec(bytes) => bytes.len(),
            FamilyId(v) => size_of_val(v),
            FamilyName(s) => s.len(),
            Version(v) => size_of_val(v),
            HdrSize(v) => size_of_val(v),
            MaxAttr(v) => size_of_val(v),
            Ops(nlas) => nlas.as_slice().buffer_len(),
            McastGroups(nlas) => nlas.as_slice().buffer_len(),
            Policy(bytes) => bytes.len(),
            OpPolicy(bytes) => bytes.len(),
            Op(v) => size_of_val(v),
            Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use GenlCtrlAttrs::*;
        match self {
            Unspec(_) => CTRL_ATTR_UNSPEC,
            FamilyId(_) => CTRL_ATTR_FAMILY_ID,
            FamilyName(_) => CTRL_ATTR_FAMILY_NAME,
            Version(_) => CTRL_ATTR_VERSION,
            HdrSize(_) => CTRL_ATTR_HDRSIZE,
            MaxAttr(_) => CTRL_ATTR_MAXATTR,
            Ops(_) => CTRL_ATTR_OPS,
            McastGroups(_) => CTRL_ATTR_MCAST_GROUPS,
            Policy(_) => CTRL_ATTR_POLICY,
            OpPolicy(_) => CTRL_ATTR_OP_POLICY,
            Op(_) => CTRL_ATTR_OP,
            Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use GenlCtrlAttrs::*;
        match self {
            Unspec(bytes) => buffer.copy_from_slice(bytes),
            FamilyId(v) => NativeEndian::write_u16(buffer, *v),
            FamilyName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Version(v) => NativeEndian::write_u32(buffer, *v),
            HdrSize(v) => NativeEndian::write_u32(buffer, *v),
            MaxAttr(v) => NativeEndian::write_u32(buffer, *v),
            Ops(nlas) => nlas.as_slice().emit(buffer),
            McastGroups(nlas) => nlas.as_slice().emit(buffer),
            Policy(bytes) => buffer.copy_from_slice(bytes),
            OpPolicy(bytes) => buffer.copy_from_slice(bytes),
            Op(v) => NativeEndian::write_u32(buffer, *v),
            Other(nla) => nla.emit_value(buffer),
        }
    }
}
