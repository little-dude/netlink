// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32,
    DecodeError,
    Emitable,
    Parseable,
};

const NL80211_TXQ_STATS_BACKLOG_BYTES: u16 = 1;
const NL80211_TXQ_STATS_BACKLOG_PACKETS: u16 = 2;
const NL80211_TXQ_STATS_FLOWS: u16 = 3;
const NL80211_TXQ_STATS_DROPS: u16 = 4;
const NL80211_TXQ_STATS_ECN_MARKS: u16 = 5;
const NL80211_TXQ_STATS_OVERLIMIT: u16 = 6;
const NL80211_TXQ_STATS_OVERMEMORY: u16 = 7;
const NL80211_TXQ_STATS_COLLISIONS: u16 = 8;
const NL80211_TXQ_STATS_TX_BYTES: u16 = 9;
const NL80211_TXQ_STATS_TX_PACKETS: u16 = 10;
const NL80211_TXQ_STATS_MAX_FLOWS: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211TransmitQueueStat {
    BacklogBytes(u32),
    BacklogPackets(u32),
    Flows(u32),
    Drops(u32),
    EcnMarks(u32),
    Overlimit(u32),
    Overmemory(u32),
    Collisions(u32),
    TxBytes(u32),
    TxPackets(u32),
    MaxFlows(u32),
    Other(DefaultNla),
}

impl Nla for Nl80211TransmitQueueStat {
    fn value_len(&self) -> usize {
        match self {
            Self::BacklogBytes(_)
            | Self::BacklogPackets(_)
            | Self::Flows(_)
            | Self::Drops(_)
            | Self::EcnMarks(_)
            | Self::Overlimit(_)
            | Self::Overmemory(_)
            | Self::Collisions(_)
            | Self::TxBytes(_)
            | Self::TxPackets(_)
            | Self::MaxFlows(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }
    fn kind(&self) -> u16 {
        match self {
            Self::BacklogBytes(_) => NL80211_TXQ_STATS_BACKLOG_BYTES,
            Self::BacklogPackets(_) => NL80211_TXQ_STATS_BACKLOG_PACKETS,
            Self::Flows(_) => NL80211_TXQ_STATS_FLOWS,
            Self::Drops(_) => NL80211_TXQ_STATS_DROPS,
            Self::EcnMarks(_) => NL80211_TXQ_STATS_ECN_MARKS,
            Self::Overlimit(_) => NL80211_TXQ_STATS_OVERLIMIT,
            Self::Overmemory(_) => NL80211_TXQ_STATS_OVERMEMORY,
            Self::Collisions(_) => NL80211_TXQ_STATS_COLLISIONS,
            Self::TxBytes(_) => NL80211_TXQ_STATS_TX_BYTES,
            Self::TxPackets(_) => NL80211_TXQ_STATS_TX_PACKETS,
            Self::MaxFlows(_) => NL80211_TXQ_STATS_MAX_FLOWS,
            Self::Other(attr) => attr.kind(),
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::BacklogBytes(d)
            | Self::BacklogPackets(d)
            | Self::Flows(d)
            | Self::Drops(d)
            | Self::EcnMarks(d)
            | Self::Overlimit(d)
            | Self::Overmemory(d)
            | Self::Collisions(d)
            | Self::TxBytes(d)
            | Self::TxPackets(d)
            | Self::MaxFlows(d) => NativeEndian::write_u32(buffer, *d),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nl80211TransmitQueueStat {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_TXQ_STATS_BACKLOG_BYTES => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_BACKLOG_BYTES value {:?}",
                    payload
                );
                Self::BacklogBytes(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_BACKLOG_PACKETS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_BACKLOG_PACKETS value: {:?}",
                    payload
                );
                Self::BacklogPackets(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_FLOWS => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_FLOWS value: {:?}", payload);
                Self::Flows(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_DROPS => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_DROPS value: {:?}", payload);
                Self::Drops(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_ECN_MARKS => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_ECN_MARKS value: {:?}", payload);
                Self::EcnMarks(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_OVERLIMIT => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_OVERLIMIT value: {:?}", payload);
                Self::Overlimit(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_OVERMEMORY => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_OVERMEMORY value: {:?}", payload);
                Self::Overmemory(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_COLLISIONS => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_COLLISIONS value: {:?}", payload);
                Self::Collisions(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_TX_BYTES => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_TX_BYTES value: {:?}", payload);
                Self::TxBytes(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_TX_PACKETS => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_TX_PACKETS value: {:?}", payload);
                Self::TxPackets(parse_u32(payload).context(err_msg)?)
            }

            NL80211_TXQ_STATS_MAX_FLOWS => {
                let err_msg = format!("Invalid NL80211_TXQ_STATS_MAX_FLOWS value: {:?}", payload);
                Self::MaxFlows(parse_u32(payload).context(err_msg)?)
            }
            _ => Self::Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}
