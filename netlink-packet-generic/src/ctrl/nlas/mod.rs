use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::*,
    traits::*,
    DecodeError,
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
    Ops(Vec<Vec<OpAttrs>>),
    McastGroups(Vec<Vec<McastGrpAttrs>>),
    Policy(Vec<DefaultNla>),
    OpPolicy(DefaultNla),
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
            Ops(nlas) => nlas.iter().map(|op| op.as_slice().buffer_len()).sum(),
            McastGroups(nlas) => nlas.iter().map(|op| op.as_slice().buffer_len()).sum(),
            Policy(nlas) => nlas.as_slice().buffer_len(),
            OpPolicy(nla) => nla.buffer_len(),
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
            Ops(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.as_slice().emit(&mut buffer[len..]);
                    len += op.as_slice().buffer_len();
                }
            }
            McastGroups(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.as_slice().emit(&mut buffer[len..]);
                    len += op.as_slice().buffer_len();
                }
            }
            Policy(nlas) => nlas.as_slice().emit(buffer),
            OpPolicy(nla) => nla.emit_value(buffer),
            Op(v) => NativeEndian::write_u32(buffer, *v),
            Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for GenlCtrlAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_UNSPEC => Self::Unspec(payload.to_vec()),
            CTRL_ATTR_FAMILY_ID => {
                Self::FamilyId(parse_u16(payload).context("invalid CTRL_ATTR_FAMILY_ID value")?)
            }
            CTRL_ATTR_FAMILY_NAME => Self::FamilyName(
                parse_string(payload).context("invalid CTRL_ATTR_FAMILY_NAME value")?,
            ),
            CTRL_ATTR_VERSION => {
                Self::Version(parse_u32(payload).context("invalid CTRL_ATTR_VERSION value")?)
            }
            CTRL_ATTR_HDRSIZE => {
                Self::HdrSize(parse_u32(payload).context("invalid CTRL_ATTR_HDRSIZE value")?)
            }
            CTRL_ATTR_MAXATTR => {
                Self::MaxAttr(parse_u32(payload).context("invalid CTRL_ATTR_MAXATTR value")?)
            }
            CTRL_ATTR_OPS => {
                let mut ops = Vec::new();
                let error_msg = "failed to parse CTRL_ATTR_OPS";
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    let mut op = Vec::new();
                    for nla in NlasIterator::new(nlas.value()) {
                        let nla = &nla.context(error_msg)?;
                        let parsed = OpAttrs::parse(nla).context(error_msg)?;
                        op.push(parsed);
                    }
                    ops.push(op);
                }
                Self::Ops(ops)
            }
            CTRL_ATTR_MCAST_GROUPS => {
                let error_msg = "failed to parse CTRL_ATTR_MCAST_GROUPS";
                let mut groups = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    let mut group = Vec::new();
                    for nla in NlasIterator::new(nlas.value()) {
                        let nla = &nla.context(error_msg)?;
                        let parsed = McastGrpAttrs::parse(nla).context(error_msg)?;
                        group.push(parsed);
                    }
                    groups.push(group);
                }
                Self::McastGroups(groups)
            }
            CTRL_ATTR_POLICY => {
                let error_msg = "failed to parse CTRL_ATTR_POLICY";
                let mut policies = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(error_msg)?;
                    let parsed = DefaultNla::parse(nla).context(error_msg)?;
                    policies.push(parsed);
                }
                Self::Policy(policies)
            },
            CTRL_ATTR_OP_POLICY => Self::OpPolicy(DefaultNla::parse(buf).context("failed to parse CTRL_ATTR_OP_POLICY")?),
            CTRL_ATTR_OP => Self::Op(parse_u32(payload)?),
            _ => Self::Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}
