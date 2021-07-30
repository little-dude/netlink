use crate::constants::*;
use anyhow::Context;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{nla::NlasIterator, traits::*, DecodeError};
use nlas::WgDeviceAttrs;
use std::convert::{TryFrom, TryInto};

pub mod constants;
pub mod nlas;
mod raw;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireguardCmd {
    GetDevice,
    SetDevice,
}

impl From<WireguardCmd> for u8 {
    fn from(cmd: WireguardCmd) -> Self {
        use WireguardCmd::*;
        match cmd {
            GetDevice => WG_CMD_GET_DEVICE,
            SetDevice => WG_CMD_SET_DEVICE,
        }
    }
}

impl TryFrom<u8> for WireguardCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use WireguardCmd::*;
        Ok(match value {
            WG_CMD_GET_DEVICE => GetDevice,
            WG_CMD_SET_DEVICE => SetDevice,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unknown wireguard command: {}",
                    cmd
                )))
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wireguard {
    pub cmd: WireguardCmd,
    pub nlas: Vec<nlas::WgDeviceAttrs>,
}

impl GenlFamily for Wireguard {
    fn family_name() -> &'static str {
        "wireguard"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Emitable for Wireguard {
    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for Wireguard {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            nlas: parse_nlas(buf)?,
        })
    }
}

fn parse_nlas(buf: &[u8]) -> Result<Vec<WgDeviceAttrs>, DecodeError> {
    let mut nlas = Vec::new();
    let error_msg = "failed to parse message attributes";
    for nla in NlasIterator::new(buf) {
        let nla = &nla.context(error_msg)?;
        let parsed = WgDeviceAttrs::parse(nla).context(error_msg)?;
        nlas.push(parsed);
    }
    Ok(nlas)
}
