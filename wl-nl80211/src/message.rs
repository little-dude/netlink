// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_core::DecodeError;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{nla::NlasIterator, Emitable, Parseable, ParseableParametrized};

use crate::attr::Nl80211Attr;

const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211Cmd {
    InterfaceGet,
    InterfaceNew,
}

impl From<Nl80211Cmd> for u8 {
    fn from(cmd: Nl80211Cmd) -> Self {
        match cmd {
            Nl80211Cmd::InterfaceGet => NL80211_CMD_GET_INTERFACE,
            Nl80211Cmd::InterfaceNew => NL80211_CMD_NEW_INTERFACE,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211Message {
    pub cmd: Nl80211Cmd,
    pub nlas: Vec<Nl80211Attr>,
}

impl GenlFamily for Nl80211Message {
    fn family_name() -> &'static str {
        "nl80211"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Nl80211Message {
    pub fn new_interface_get() -> Self {
        Nl80211Message {
            cmd: Nl80211Cmd::InterfaceGet,
            nlas: vec![],
        }
    }
}

impl Emitable for Nl80211Message {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }
}

fn parse_nlas(buffer: &[u8]) -> Result<Vec<Nl80211Attr>, DecodeError> {
    let mut nlas = Vec::new();
    for nla in NlasIterator::new(buffer) {
        let error_msg = format!("Failed to parse nl80211 message attribute {:?}", nla);
        let nla = &nla.context(error_msg.clone())?;
        nlas.push(Nl80211Attr::parse(nla).context(error_msg)?);
    }
    Ok(nlas)
}

impl ParseableParametrized<[u8], GenlHeader> for Nl80211Message {
    fn parse_with_param(buffer: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(match header.cmd {
            NL80211_CMD_NEW_INTERFACE => Self {
                cmd: Nl80211Cmd::InterfaceNew,
                nlas: parse_nlas(buffer)?,
            },
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unsupported nl80211 reply command: {}",
                    cmd
                )))
            }
        })
    }
}
