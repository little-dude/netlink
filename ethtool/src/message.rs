use std::convert::{TryFrom, TryInto};

use netlink_packet_core::DecodeError;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{nla::Nla, Emitable, ParseableParametrized};

use crate::{
    pause::{parse_pause_nlas, EthtoolPauseAttr},
    EthtoolHeader,
};

const ETHTOOL_MSG_PAUSE_GET: u8 = 21;
const ETHTOOL_MSG_PAUSE_GET_REPLY: u8 = 22;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolCmd {
    PauseGet,
    PauseGetReply,
}

impl From<EthtoolCmd> for u8 {
    fn from(cmd: EthtoolCmd) -> Self {
        match cmd {
            EthtoolCmd::PauseGet => ETHTOOL_MSG_PAUSE_GET,
            EthtoolCmd::PauseGetReply => ETHTOOL_MSG_PAUSE_GET_REPLY,
        }
    }
}

impl TryFrom<u8> for EthtoolCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            ETHTOOL_MSG_PAUSE_GET => Self::PauseGet,
            ETHTOOL_MSG_PAUSE_GET_REPLY => Self::PauseGetReply,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unsupported ethtool command: {}",
                    cmd
                )))
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolAttr {
    Pause(EthtoolPauseAttr),
}

impl Nla for EthtoolAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Pause(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Pause(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Pause(attr) => attr.emit_value(buffer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthtoolMessage {
    pub cmd: EthtoolCmd,
    pub nlas: Vec<EthtoolAttr>,
}

impl GenlFamily for EthtoolMessage {
    fn family_name() -> &'static str {
        "ethtool"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl EthtoolMessage {
    pub fn new_pause_get(iface_name: Option<&str>) -> Self {
        let nlas = match iface_name {
            Some(s) => vec![EthtoolAttr::Pause(EthtoolPauseAttr::Header(vec![
                EthtoolHeader::DevName(s.to_string()),
            ]))],
            None => vec![EthtoolAttr::Pause(EthtoolPauseAttr::Header(vec![]))],
        };
        EthtoolMessage {
            cmd: EthtoolCmd::PauseGet,
            nlas,
        }
    }
}

impl Emitable for EthtoolMessage {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }
}

impl ParseableParametrized<[u8], GenlHeader> for EthtoolMessage {
    fn parse_with_param(buffer: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        let cmd = header.cmd.try_into()?;
        let nlas = match cmd {
            EthtoolCmd::PauseGetReply => parse_pause_nlas(buffer)?,
            _ => return Err(format!("Unsupported ethtool command {:?}", cmd).into()),
        };
        Ok(Self { cmd, nlas })
    }
}
