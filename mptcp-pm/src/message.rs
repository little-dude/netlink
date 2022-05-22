// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_core::DecodeError;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlasIterator},
    Emitable,
    Parseable,
    ParseableParametrized,
};

use crate::{address::MptcpPathManagerAddressAttr, limits::MptcpPathManagerLimitsAttr};

const MPTCP_PM_CMD_GET_ADDR: u8 = 3;
const MPTCP_PM_CMD_GET_LIMITS: u8 = 6;

const MPTCP_PM_ATTR_ADDR: u16 = 1;
const MPTCP_PM_ATTR_RCV_ADD_ADDRS: u16 = 2;
const MPTCP_PM_ATTR_SUBFLOWS: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MptcpPathManagerCmd {
    AddressGet,
    LimitsGet,
}

impl From<MptcpPathManagerCmd> for u8 {
    fn from(cmd: MptcpPathManagerCmd) -> Self {
        match cmd {
            MptcpPathManagerCmd::AddressGet => MPTCP_PM_CMD_GET_ADDR,
            MptcpPathManagerCmd::LimitsGet => MPTCP_PM_CMD_GET_LIMITS,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MptcpPathManagerAttr {
    Address(MptcpPathManagerAddressAttr),
    Limits(MptcpPathManagerLimitsAttr),
    Other(DefaultNla),
}

impl Nla for MptcpPathManagerAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Address(attr) => attr.value_len(),
            Self::Limits(attr) => attr.value_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Address(attr) => attr.kind(),
            Self::Limits(attr) => attr.kind(),
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Address(attr) => attr.emit_value(buffer),
            Self::Limits(attr) => attr.emit_value(buffer),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MptcpPathManagerMessage {
    pub cmd: MptcpPathManagerCmd,
    pub nlas: Vec<MptcpPathManagerAttr>,
}

impl GenlFamily for MptcpPathManagerMessage {
    fn family_name() -> &'static str {
        "mptcp_pm"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl MptcpPathManagerMessage {
    pub fn new_address_get() -> Self {
        MptcpPathManagerMessage {
            cmd: MptcpPathManagerCmd::AddressGet,
            nlas: vec![],
        }
    }

    pub fn new_limits_get() -> Self {
        MptcpPathManagerMessage {
            cmd: MptcpPathManagerCmd::LimitsGet,
            nlas: vec![],
        }
    }
}

impl Emitable for MptcpPathManagerMessage {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }
}

fn parse_nlas(buffer: &[u8]) -> Result<Vec<MptcpPathManagerAttr>, DecodeError> {
    let mut nlas = Vec::new();
    for nla in NlasIterator::new(buffer) {
        let error_msg = format!("Failed to parse mptcp address message attribute {:?}", nla);
        let nla = &nla.context(error_msg)?;
        match nla.kind() {
            MPTCP_PM_ATTR_ADDR => {
                for addr_nla in NlasIterator::new(nla.value()) {
                    let error_msg = format!("Failed to parse MPTCP_PM_ATTR_ADDR {:?}", addr_nla);
                    let addr_nla = &addr_nla.context(error_msg)?;

                    nlas.push(MptcpPathManagerAttr::Address(
                        MptcpPathManagerAddressAttr::parse(addr_nla)
                            .context("Failed to parse MPTCP_PM_ATTR_ADDR")?,
                    ))
                }
            }
            MPTCP_PM_ATTR_RCV_ADD_ADDRS => nlas.push(MptcpPathManagerAttr::Limits(
                MptcpPathManagerLimitsAttr::parse(nla)
                    .context("Failed to parse MPTCP_PM_ATTR_RCV_ADD_ADDRS")?,
            )),
            MPTCP_PM_ATTR_SUBFLOWS => nlas.push(MptcpPathManagerAttr::Limits(
                MptcpPathManagerLimitsAttr::parse(nla)
                    .context("Failed to parse MPTCP_PM_ATTR_RCV_ADD_ADDRS")?,
            )),
            _ => nlas.push(MptcpPathManagerAttr::Other(
                DefaultNla::parse(nla).context("invalid NLA (unknown kind)")?,
            )),
        }
    }
    Ok(nlas)
}

impl ParseableParametrized<[u8], GenlHeader> for MptcpPathManagerMessage {
    fn parse_with_param(buffer: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(match header.cmd {
            MPTCP_PM_CMD_GET_ADDR => Self {
                cmd: MptcpPathManagerCmd::AddressGet,
                nlas: parse_nlas(buffer)?,
            },
            MPTCP_PM_CMD_GET_LIMITS => Self {
                cmd: MptcpPathManagerCmd::LimitsGet,
                nlas: parse_nlas(buffer)?,
            },
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unsupported mptcp reply command: {}",
                    cmd
                )))
            }
        })
    }
}
