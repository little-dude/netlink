use failure::ResultExt;

use crate::constants::*;
use crate::{DecodeError, DefaultNla, Emitable, Nla, NlaBuffer, Parseable};

mod dev_conf;
pub use self::dev_conf::*;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum LinkAfInetNla {
    DevConf(LinkInetDevConf),
    Unspec(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for LinkAfInetNla {
    fn value_len(&self) -> usize {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            DevConf(_) => LINK_INET_DEV_CONF_LEN,
            Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(ref bytes) => (&mut buffer[..bytes.len()]).copy_from_slice(bytes.as_slice()),
            DevConf(ref dev_conf) => dev_conf.emit(buffer),
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkAfInetNla::*;
        match *self {
            Unspec(_) => IFLA_INET_UNSPEC,
            DevConf(_) => IFLA_INET_CONF,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<LinkAfInetNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<LinkAfInetNla, DecodeError> {
        use self::LinkAfInetNla::*;

        self.check_buffer_length()?;

        let payload = self.value();
        Ok(match self.kind() {
            IFLA_INET_UNSPEC => Unspec(payload.to_vec()),
            IFLA_INET_CONF => DevConf(
                LinkInetDevConfBuffer::new(payload)
                    .parse()
                    .context("invalid IFLA_INET_CONF value")?,
            ),
            kind => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context(format!("unknown NLA type {}", kind))?,
            ),
        })
    }
}
