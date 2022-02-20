use anyhow::Context;
use byteorder::{BigEndian, ByteOrder};
use derive_more::{From, IsVariant};

use crate::{
    constants::{
        NFULA_CFG_CMD,
        NFULA_CFG_FLAGS,
        NFULA_CFG_MODE,
        NFULA_CFG_NLBUFSIZ,
        NFULA_CFG_QTHRESH,
        NFULA_CFG_TIMEOUT,
    },
    nflog::nlas::config::{
        config_mode::ConfigModeBuffer,
        ConfigCmd,
        ConfigFlags,
        ConfigMode,
        Timeout,
    },
    nl::DecodeError,
    nla::{DefaultNla, Nla, NlaBuffer},
    traits::Parseable,
    utils::parsers::{parse_u16_be, parse_u32_be, parse_u8},
};

#[derive(Clone, Debug, PartialEq, Eq, From, IsVariant)]
pub enum ConfigNla {
    Cmd(ConfigCmd),
    Mode(ConfigMode),
    #[from(ignore)]
    NlBufSiz(u32),
    Timeout(Timeout),
    #[from(ignore)]
    QThresh(u32),
    Flags(ConfigFlags),
    Other(DefaultNla),
}

impl Nla for ConfigNla {
    fn value_len(&self) -> usize {
        match self {
            ConfigNla::Cmd(attr) => attr.value_len(),
            ConfigNla::Mode(attr) => attr.value_len(),
            ConfigNla::NlBufSiz(_) => 4,
            ConfigNla::Timeout(attr) => attr.value_len(),
            ConfigNla::QThresh(_) => 4,
            ConfigNla::Flags(attr) => attr.value_len(),
            ConfigNla::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConfigNla::Cmd(attr) => attr.kind(),
            ConfigNla::Mode(attr) => attr.kind(),
            ConfigNla::NlBufSiz(_) => NFULA_CFG_NLBUFSIZ,
            ConfigNla::Timeout(attr) => attr.kind(),
            ConfigNla::QThresh(_) => NFULA_CFG_QTHRESH,
            ConfigNla::Flags(attr) => attr.kind(),
            ConfigNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ConfigNla::Cmd(attr) => attr.emit_value(buffer),
            ConfigNla::Mode(attr) => attr.emit_value(buffer),
            ConfigNla::NlBufSiz(buf_siz) => BigEndian::write_u32(buffer, *buf_siz),
            ConfigNla::Timeout(attr) => attr.emit_value(buffer),
            ConfigNla::QThresh(q_thresh) => BigEndian::write_u32(buffer, *q_thresh),
            ConfigNla::Flags(attr) => attr.emit_value(buffer),
            ConfigNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for ConfigNla {
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            NFULA_CFG_CMD => {
                ConfigCmd::from(parse_u8(payload).context("invalid NFULA_CFG_CMD value")?).into()
            }
            NFULA_CFG_MODE => {
                let buf = ConfigModeBuffer::new_checked(payload)?;
                ConfigMode::parse(&buf)?.into()
            }
            NFULA_CFG_NLBUFSIZ => ConfigNla::NlBufSiz(
                parse_u32_be(payload).context("invalid NFULA_CFG_NLBUFSIZ value")?,
            ),
            NFULA_CFG_TIMEOUT => {
                Timeout::new(parse_u32_be(payload).context("invalid NFULA_CFG_TIMEOUT value")?)
                    .into()
            }
            NFULA_CFG_QTHRESH => ConfigNla::QThresh(
                parse_u32_be(payload).context("invalid NFULA_CFG_QTHRESH value")?,
            ),
            NFULA_CFG_FLAGS => ConfigFlags::from_bits_preserve(
                parse_u16_be(payload).context("invalid NFULA_CFG_FLAGS value")?,
            )
            .into(),
            _ => ConfigNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
