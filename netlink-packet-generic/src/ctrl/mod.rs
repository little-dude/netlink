//! Generic netlink controller implementation
//!
//! This module provide the definition of the controller packet.
//! It also serves as an example for creating a generic family.

use self::nlas::*;
use crate::{GenlHeader, constants::*};
use crate::traits::*;

use anyhow::Context;
use netlink_packet_utils::{
    nla::{NlasIterator},
    traits::*,
    DecodeError,
};

/// Netlink attributes for this family
pub mod nlas;

/// Payload of generic netlink controller
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenlCtrl {
    Unspec(Vec<u8>),
    /// Notify from event
    NewFamily(Vec<GenlCtrlAttrs>),
    /// Notify from event
    DelFamily(Vec<GenlCtrlAttrs>),
    /// Request to get family info
    GetFamily(Vec<GenlCtrlAttrs>),
    /// Currently unused
    NewOps(Vec<u8>),
    /// Currently unused
    DelOps(Vec<u8>),
    /// Currently unused
    GetOps(Vec<u8>),
    /// Notify from event
    NewMcastGrp(Vec<GenlCtrlAttrs>),
    /// Notify from event
    DelMcastGrp(Vec<GenlCtrlAttrs>),
    /// Currently unused
    GetMcastGrp(Vec<u8>),
    /// Request to get family policy
    GetPolicy(Vec<GenlCtrlAttrs>),
}

impl GenlFamily for GenlCtrl {
    fn family_name(&self) -> &'static str {
        "nlctrl"
    }

    fn family_id(&self) -> u16 {
        GENL_ID_CTRL
    }

    fn command(&self) -> u8 {
        use GenlCtrl::*;
        match self {
            Unspec(_) => CTRL_CMD_UNSPEC,
            NewFamily(_) => CTRL_CMD_NEWFAMILY,
            DelFamily(_) => CTRL_CMD_DELFAMILY,
            GetFamily(_) => CTRL_CMD_GETFAMILY,
            NewOps(_) => CTRL_CMD_NEWOPS,
            DelOps(_) => CTRL_CMD_DELOPS,
            GetOps(_) => CTRL_CMD_GETOPS,
            NewMcastGrp(_) => CTRL_CMD_NEWMCAST_GRP,
            DelMcastGrp(_) => CTRL_CMD_DELMCAST_GRP,
            GetMcastGrp(_) => CTRL_CMD_GETMCAST_GRP,
            GetPolicy(_) => CTRL_CMD_GETPOLICY,
        }
    }

    fn version(&self) -> u8 {
        2
    }
}

impl Emitable for GenlCtrl {
    fn emit(&self, buffer: &mut [u8]) {
        use GenlCtrl::*;
        match self {
            Unspec(bytes) => buffer.copy_from_slice(bytes),
            NewFamily(nlas) => nlas.as_slice().emit(buffer),
            DelFamily(nlas) => nlas.as_slice().emit(buffer),
            GetFamily(nlas) => nlas.as_slice().emit(buffer),
            NewOps(bytes) => buffer.copy_from_slice(bytes),
            DelOps(bytes) => buffer.copy_from_slice(bytes),
            GetOps(bytes) => buffer.copy_from_slice(bytes),
            NewMcastGrp(nlas) => nlas.as_slice().emit(buffer),
            DelMcastGrp(nlas) => nlas.as_slice().emit(buffer),
            GetMcastGrp(bytes) => buffer.copy_from_slice(bytes),
            GetPolicy(nlas) => nlas.as_slice().emit(buffer),
        }
    }

    fn buffer_len(&self) -> usize {
        use GenlCtrl::*;
        match self {
            Unspec(bytes) => bytes.len(),
            NewFamily(nlas) => nlas.as_slice().buffer_len(),
            DelFamily(nlas) => nlas.as_slice().buffer_len(),
            GetFamily(nlas) => nlas.as_slice().buffer_len(),
            NewOps(bytes) => bytes.len(),
            DelOps(bytes) => bytes.len(),
            GetOps(bytes) => bytes.len(),
            NewMcastGrp(nlas) => nlas.as_slice().buffer_len(),
            DelMcastGrp(nlas) => nlas.as_slice().buffer_len(),
            GetMcastGrp(bytes) => bytes.len(),
            GetPolicy(nlas) => nlas.as_slice().buffer_len(),
        }
    }
}

impl ParseableParametrized<[u8], GenlHeader> for GenlCtrl {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        use GenlCtrl::*;
        Ok(match header.cmd {
            CTRL_CMD_UNSPEC => Unspec(buf.to_vec()),
            CTRL_CMD_NEWFAMILY => NewFamily(parse_ctrlnlas(buf)?),
            CTRL_CMD_DELFAMILY=> NewFamily(parse_ctrlnlas(buf)?),
            CTRL_CMD_GETFAMILY=> NewFamily(parse_ctrlnlas(buf)?),
            CTRL_CMD_NEWOPS=> NewOps(buf.to_vec()),
            CTRL_CMD_DELOPS=> DelOps(buf.to_vec()),
            CTRL_CMD_GETOPS=> GetOps(buf.to_vec()),
            CTRL_CMD_NEWMCAST_GRP=> NewFamily(parse_ctrlnlas(buf)?),
            CTRL_CMD_DELMCAST_GRP=> NewFamily(parse_ctrlnlas(buf)?),
            CTRL_CMD_GETMCAST_GRP=> GetMcastGrp(buf.to_vec()),
            CTRL_CMD_GETPOLICY=> NewFamily(parse_ctrlnlas(buf)?),
            _ => return Err(DecodeError::from("Unknown control command")),
        })
    }
}

fn parse_ctrlnlas(buf: &[u8]) -> Result<Vec<GenlCtrlAttrs>, DecodeError> {
    let mut nlas = Vec::new();
    let error_msg = "failed to parse control message attributes";
    for nla in NlasIterator::new(buf) {
        let nla = &nla.context(error_msg)?;
        let parsed = GenlCtrlAttrs::parse(nla).context(error_msg)?;
        nlas.push(parsed);
    }
    Ok(nlas)
}
