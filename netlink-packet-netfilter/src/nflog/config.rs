use anyhow::Context;
use byteorder::{BigEndian, ByteOrder};
use netlink_packet_core::{
    DecodeError,
    NetlinkHeader,
    NetlinkMessage,
    NetlinkPayload,
    NLM_F_ACK,
    NLM_F_REQUEST,
};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16_be, parse_u32_be, parse_u8},
    Parseable,
};

pub use config_cmd::ConfigCmd;
pub use config_flags::ConfigFlags;
pub use config_mode::{ConfigMode, CopyMode};
pub use timeout::Timeout;

use crate::{
    constants::NFNETLINK_V0,
    message::{NetfilterHeader, NetfilterMessage},
};

use super::NfLogMessage;

mod config_cmd;
mod config_flags;
mod config_mode;
mod timeout;

pub const NFULA_CFG_CMD: u16 = libc::NFULA_CFG_CMD as u16;
pub const NFULA_CFG_MODE: u16 = libc::NFULA_CFG_MODE as u16;
pub const NFULA_CFG_NLBUFSIZ: u16 = libc::NFULA_CFG_NLBUFSIZ as u16;
pub const NFULA_CFG_TIMEOUT: u16 = libc::NFULA_CFG_TIMEOUT as u16;
pub const NFULA_CFG_QTHRESH: u16 = libc::NFULA_CFG_QTHRESH as u16;
pub const NFULA_CFG_FLAGS: u16 = libc::NFULA_CFG_FLAGS as u16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigNlas {
    Cmd(ConfigCmd),
    Mode(ConfigMode),
    NlBufSiz(u32),
    Timeout(Timeout),
    QThresh(u32),
    Flags(ConfigFlags),
    Other(DefaultNla),
}

impl From<ConfigCmd> for ConfigNlas {
    fn from(cmd: ConfigCmd) -> Self {
        ConfigNlas::Cmd(cmd)
    }
}

impl From<ConfigMode> for ConfigNlas {
    fn from(mode: ConfigMode) -> Self {
        ConfigNlas::Mode(mode)
    }
}

impl From<Timeout> for ConfigNlas {
    fn from(timeout: Timeout) -> Self {
        ConfigNlas::Timeout(timeout)
    }
}

impl From<ConfigFlags> for ConfigNlas {
    fn from(flags: ConfigFlags) -> Self {
        ConfigNlas::Flags(flags)
    }
}

impl Nla for ConfigNlas {
    fn value_len(&self) -> usize {
        match self {
            ConfigNlas::Cmd(attr) => attr.value_len(),
            ConfigNlas::Mode(attr) => attr.value_len(),
            ConfigNlas::NlBufSiz(_) => 4,
            ConfigNlas::Timeout(attr) => attr.value_len(),
            ConfigNlas::QThresh(_) => 4,
            ConfigNlas::Flags(attr) => attr.value_len(),
            ConfigNlas::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConfigNlas::Cmd(attr) => attr.kind(),
            ConfigNlas::Mode(attr) => attr.kind(),
            ConfigNlas::NlBufSiz(_) => NFULA_CFG_NLBUFSIZ,
            ConfigNlas::Timeout(attr) => attr.kind(),
            ConfigNlas::QThresh(_) => NFULA_CFG_QTHRESH,
            ConfigNlas::Flags(attr) => attr.kind(),
            ConfigNlas::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ConfigNlas::Cmd(attr) => attr.emit_value(buffer),
            ConfigNlas::Mode(attr) => attr.emit_value(buffer),
            ConfigNlas::NlBufSiz(buf_siz) => BigEndian::write_u32(buffer, *buf_siz),
            ConfigNlas::Timeout(attr) => attr.emit_value(buffer),
            ConfigNlas::QThresh(q_thresh) => BigEndian::write_u32(buffer, *q_thresh),
            ConfigNlas::Flags(attr) => attr.emit_value(buffer),
            ConfigNlas::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for ConfigNlas {
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            NFULA_CFG_CMD => {
                ConfigCmd::from(parse_u8(payload).context("invalid NFULA_CFG_CMD value")?).into()
            }
            NFULA_CFG_MODE => {
                let buf = config_mode::ConfigModeBuffer::new_checked(payload)?;
                ConfigMode::parse(&buf)?.into()
            }
            NFULA_CFG_NLBUFSIZ => ConfigNlas::NlBufSiz(
                parse_u32_be(payload).context("invalid NFULA_CFG_NLBUFSIZ value")?,
            ),
            NFULA_CFG_TIMEOUT => {
                Timeout::new(parse_u32_be(payload).context("invalid NFULA_CFG_TIMEOUT value")?)
                    .into()
            }
            NFULA_CFG_QTHRESH => ConfigNlas::QThresh(
                parse_u32_be(payload).context("invalid NFULA_CFG_QTHRESH value")?,
            ),
            NFULA_CFG_FLAGS => ConfigFlags::from_bits_truncate(parse_u16_be(payload)?).into(),
            _ => ConfigNlas::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}

pub fn config_request(
    family: u8,
    group_num: u16,
    nlas: Vec<ConfigNlas>,
) -> NetlinkMessage<NetfilterMessage> {
    let mut message = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_ACK,
            ..Default::default()
        },
        payload: NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, group_num),
            NfLogMessage::Config(nlas),
        )),
    };
    message.finalize();
    message
}
