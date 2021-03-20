//! Generic netlink controller implementation
//!
//! This module provide the definition of the controller packet.
//! It also serves as an example for creating a generic family.

use self::nlas::*;
use crate::constants::*;
use crate::traits::*;

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
    NewMcastGrp,
    /// Notify from event
    DelMcastGrp,
    /// Currently unused
    GetMcastGrp(Vec<u8>),
    /// Request to get family policy
    GetPolicy,
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
            NewMcastGrp => CTRL_CMD_NEWMCAST_GRP,
            DelMcastGrp => CTRL_CMD_DELMCAST_GRP,
            GetMcastGrp(_) => CTRL_CMD_GETMCAST_GRP,
            GetPolicy => CTRL_CMD_GETPOLICY,
        }
    }

    fn version(&self) -> u8 {
        2
    }
}
