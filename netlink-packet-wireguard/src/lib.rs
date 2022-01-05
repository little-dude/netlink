#[macro_use]
extern crate log;

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

#[cfg(test)]

mod test {
    use std::net::Ipv4Addr;

    use netlink_packet_core::{NetlinkMessage, NLM_F_REQUEST, NLM_F_ACK};
    use netlink_packet_generic::GenlMessage;

    use crate::nlas::{WgPeerAttrs, WgAllowedIpAttrs};

    use super::*;

    const KNOWN_VALID_PACKET: &[u8] = &[
        0x74, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x05, 0x00,
        0x38, 0x24, 0xd6, 0x61, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x00,
        0x66, 0x72, 0x61, 0x6e, 0x64, 0x73, 0x00, 0x00,
        0x54, 0x00, 0x08, 0x80, 0x50, 0x00, 0x00, 0x80,
        0x24, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0x03, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x09, 0x80,
        0x1c, 0x00, 0x00, 0x80, 0x06, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x0a, 0x0a, 0x0a, 0x0a, 0x05, 0x00, 0x03, 0x00,
        0x1e, 0x00, 0x00, 0x00
      ];

    #[test]
    fn test_parse_known_valid_packet() {
        NetlinkMessage::<GenlMessage<Wireguard>>::deserialize(KNOWN_VALID_PACKET).unwrap();
    }

    #[test]
    fn test_serialize_then_deserialize() {
        let genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
            cmd: WireguardCmd::SetDevice,
            nlas: vec![
                WgDeviceAttrs::IfName("wg0".to_string()),
                WgDeviceAttrs::PrivateKey([0xaa; 32]),
                WgDeviceAttrs::Peers(vec![
                    vec![
                        WgPeerAttrs::PublicKey([0x01; 32]),
                        WgPeerAttrs::PresharedKey([0x01; 32]),
                        WgPeerAttrs::AllowedIps(vec![vec![WgAllowedIpAttrs::IpAddr([10, 0, 0, 0].into()), WgAllowedIpAttrs::Cidr(24), WgAllowedIpAttrs::Family(AF_INET)]])
                    ],
                    vec![WgPeerAttrs::PublicKey([0x02; 32]),
                        WgPeerAttrs::PresharedKey([0x01; 32]),
                        WgPeerAttrs::AllowedIps(vec![vec![WgAllowedIpAttrs::IpAddr([10, 0, 1, 0].into()), WgAllowedIpAttrs::Cidr(24), WgAllowedIpAttrs::Family(AF_INET)]])
                    ],
                ]),
            ],
        });
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        nlmsg.finalize();
        let mut buf = [0; 4096];
        nlmsg.serialize(&mut buf);
        let len = nlmsg.buffer_len();
        NetlinkMessage::<GenlMessage<Wireguard>>::deserialize(&buf[..len]).unwrap();
    }
}
