use super::{WgAllowedIpAttrs, NestedSlice};
use crate::{
    constants::*,
    raw::{
        emit_socket_addr,
        emit_timespec,
        parse_socket_addr,
        parse_timespec,
        SOCKET_ADDR_V4_LEN,
        SOCKET_ADDR_V6_LEN,
        TIMESPEC_LEN,
    },
};
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::{convert::TryInto, mem::size_of_val, net::SocketAddr, time::SystemTime};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WgPeerAttrs {
    Unspec(Vec<u8>),
    PublicKey([u8; WG_KEY_LEN]),
    PresharedKey([u8; WG_KEY_LEN]),
    Endpoint(SocketAddr),
    PersistentKeepalive(u16),
    LastHandshake(SystemTime),
    RxBytes(u64),
    TxBytes(u64),
    AllowedIps(Vec<Vec<WgAllowedIpAttrs>>),
    ProtocolVersion(u32),
    Flags(u32),
}

impl Nla for WgPeerAttrs {
    fn value_len(&self) -> usize {
        match self {
            WgPeerAttrs::Unspec(bytes) => bytes.len(),
            WgPeerAttrs::PublicKey(v) => size_of_val(v),
            WgPeerAttrs::PresharedKey(v) => size_of_val(v),
            WgPeerAttrs::Endpoint(v) => match *v {
                SocketAddr::V4(_) => SOCKET_ADDR_V4_LEN,
                SocketAddr::V6(_) => SOCKET_ADDR_V6_LEN,
            },
            WgPeerAttrs::PersistentKeepalive(v) => size_of_val(v),
            WgPeerAttrs::LastHandshake(_) => TIMESPEC_LEN,
            WgPeerAttrs::RxBytes(v) => size_of_val(v),
            WgPeerAttrs::TxBytes(v) => size_of_val(v),
            WgPeerAttrs::AllowedIps(nlas) => nlas.iter().map(|op| NestedSlice(op).buffer_len()).sum(),
            WgPeerAttrs::ProtocolVersion(v) => size_of_val(v),
            WgPeerAttrs::Flags(v) => size_of_val(v),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            WgPeerAttrs::Unspec(_) => WGPEER_A_UNSPEC,
            WgPeerAttrs::PublicKey(_) => WGPEER_A_PUBLIC_KEY,
            WgPeerAttrs::PresharedKey(_) => WGPEER_A_PRESHARED_KEY,
            WgPeerAttrs::Endpoint(_) => WGPEER_A_ENDPOINT,
            WgPeerAttrs::PersistentKeepalive(_) => WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
            WgPeerAttrs::LastHandshake(_) => WGPEER_A_LAST_HANDSHAKE_TIME,
            WgPeerAttrs::RxBytes(_) => WGPEER_A_RX_BYTES,
            WgPeerAttrs::TxBytes(_) => WGPEER_A_TX_BYTES,
            WgPeerAttrs::AllowedIps(_) => WGPEER_A_ALLOWEDIPS,
            WgPeerAttrs::ProtocolVersion(_) => WGPEER_A_PROTOCOL_VERSION,
            WgPeerAttrs::Flags(_) => WGPEER_A_FLAGS,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            WgPeerAttrs::Unspec(bytes) => buffer.copy_from_slice(bytes),
            WgPeerAttrs::PublicKey(v) => buffer.copy_from_slice(v),
            WgPeerAttrs::PresharedKey(v) => buffer.copy_from_slice(v),
            WgPeerAttrs::Endpoint(v) => emit_socket_addr(v, buffer),
            WgPeerAttrs::PersistentKeepalive(v) => NativeEndian::write_u16(buffer, *v),
            WgPeerAttrs::LastHandshake(v) => emit_timespec(v, buffer),
            WgPeerAttrs::RxBytes(v) => NativeEndian::write_u64(buffer, *v),
            WgPeerAttrs::TxBytes(v) => NativeEndian::write_u64(buffer, *v),
            WgPeerAttrs::AllowedIps(nlas) => {
                let mut len = 0;
                for op in nlas {
                    let entry = NestedSlice(op);
                    entry.emit(&mut buffer[len..]);
                    len += entry.buffer_len();
                }
            }
            WgPeerAttrs::ProtocolVersion(v) => NativeEndian::write_u32(buffer, *v),
            WgPeerAttrs::Flags(v) => NativeEndian::write_u32(buffer, *v),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, WgPeerAttrs::AllowedIps(_))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for WgPeerAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            WGPEER_A_UNSPEC => Self::Unspec(payload.to_vec()),
            WGPEER_A_PUBLIC_KEY => {
                Self::PublicKey(payload.try_into().context("invalid WGPEER_A_PUBLIC_KEY")?)
            }
            WGPEER_A_PRESHARED_KEY => Self::PresharedKey(
                payload
                    .try_into()
                    .context("invalid WGPEER_A_PRESHARED_KEY")?,
            ),
            WGPEER_A_ENDPOINT => {
                Self::Endpoint(parse_socket_addr(payload).context("invalid WGPEER_A_ENDPOINT")?)
            }
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => Self::PersistentKeepalive(
                parse_u16(payload)
                    .context("invalid WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL value")?,
            ),
            WGPEER_A_LAST_HANDSHAKE_TIME => Self::LastHandshake(
                parse_timespec(payload).context("invalid WGPEER_A_LAST_HANDSHAKE_TIME")?,
            ),
            WGPEER_A_RX_BYTES => {
                Self::RxBytes(parse_u64(payload).context("invalid WGPEER_A_RX_BYTES value")?)
            }
            WGPEER_A_TX_BYTES => {
                Self::TxBytes(parse_u64(payload).context("invalid WGPEER_A_TX_BYTES value")?)
            }
            WGPEER_A_ALLOWEDIPS => {
                let error_msg = "failed to parse WGPEER_A_ALLOWEDIPS";
                let mut ips = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    let mut group = Vec::new();
                    for nla in NlasIterator::new(nlas.value()) {
                        let nla = &nla.context(error_msg)?;
                        let parsed = WgAllowedIpAttrs::parse(nla).context(error_msg)?;
                        group.push(parsed);
                    }
                    ips.push(group);
                }
                Self::AllowedIps(ips)
            }
            WGPEER_A_PROTOCOL_VERSION => Self::ProtocolVersion(
                parse_u32(payload).context("invalid WGPEER_A_PROTOCOL_VERSION value")?,
            ),
            WGPEER_A_FLAGS => {
                Self::Flags(parse_u32(payload).context("invalid WGPEER_A_FLAGS value")?)
            }
            kind => return Err(DecodeError::from(format!("invalid NLA kind: {}", kind))),
        })
    }
}
