//! Generic netlink controller implementation
//!
//! This module provide the definition of the controller packet.
//! It also serves as an example for creating a generic family.

use crate::constants::*;
use crate::traits::*;

/// Netlink attributes for this family
pub mod nlas;

/// Payload of generic netlink controller
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenlCtrl {
    Unspec,
    /// Notify from event
    NewFamily,
    /// Notify from event
    DelFamily,
    /// Request to get family info
    GetFamily,
    /// Currently unused
    NewOps,
    /// Currently unused
    DelOps,
    /// Currently unused
    GetOps,
    /// Notify from event
    NewMcastGrp,
    /// Notify from event
    DelMcastGrp,
    /// Currently unused
    GetMcastGrp,
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
            Unspec => CTRL_CMD_UNSPEC,
            NewFamily => CTRL_CMD_NEWFAMILY,
            DelFamily => CTRL_CMD_DELFAMILY,
            GetFamily => CTRL_CMD_GETFAMILY,
            NewOps => CTRL_CMD_NEWOPS,
            DelOps => CTRL_CMD_DELOPS,
            GetOps => CTRL_CMD_GETOPS,
            NewMcastGrp => CTRL_CMD_NEWMCAST_GRP,
            DelMcastGrp => CTRL_CMD_DELMCAST_GRP,
            GetMcastGrp => CTRL_CMD_GETMCAST_GRP,
            GetPolicy => CTRL_CMD_GETPOLICY,
        }
    }

    fn version(&self) -> u8 {
        2
    }
}
