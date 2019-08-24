use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;
use std::mem::size_of;

use crate::{
    rtnl::{
        nla::{DefaultNla, Nla, NlaBuffer},
        traits::Parseable,
        utils::parse_u32,
    },
    DecodeError,
};

pub const RTAX_UNSPEC: u16 = 0;
pub const RTAX_LOCK: u16 = 1;
pub const RTAX_MTU: u16 = 2;
pub const RTAX_WINDOW: u16 = 3;
pub const RTAX_RTT: u16 = 4;
pub const RTAX_RTTVAR: u16 = 5;
pub const RTAX_SSTHRESH: u16 = 6;
pub const RTAX_CWND: u16 = 7;
pub const RTAX_ADVMSS: u16 = 8;
pub const RTAX_REORDERING: u16 = 9;
pub const RTAX_HOPLIMIT: u16 = 10;
pub const RTAX_INITCWND: u16 = 11;
pub const RTAX_FEATURES: u16 = 12;
pub const RTAX_RTO_MIN: u16 = 13;
pub const RTAX_INITRWND: u16 = 14;
pub const RTAX_QUICKACK: u16 = 15;
pub const RTAX_CC_ALGO: u16 = 16;
pub const RTAX_FASTOPEN_NO_COOKIE: u16 = 17;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouteMetricsNla {
    Unspec(Vec<u8>),
    Lock(u32),
    Mtu(u32),
    Window(u32),
    Rtt(u32),
    RttVar(u32),
    SsThresh(u32),
    Cwnd(u32),
    Advmss(u32),
    Reordering(u32),
    Hoplimit(u32),
    InitCwnd(u32),
    Features(u32),
    RtoMin(u32),
    InitRwnd(u32),
    QuickAck(u32),
    CcAlgo(u32),
    FastopenNoCookie(u32),
    Other(DefaultNla),
}

impl Nla for RouteMetricsNla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::RouteMetricsNla::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            Lock(_)
                | Mtu(_)
                | Window(_)
                | Rtt(_)
                | RttVar(_)
                | SsThresh(_)
                | Cwnd(_)
                | Advmss(_)
                | Reordering(_)
                | Hoplimit(_)
                | InitCwnd(_)
                | Features(_)
                | RtoMin(_)
                | InitRwnd(_)
                | QuickAck(_)
                | CcAlgo(_)
                | FastopenNoCookie(_)
                => size_of::<u32>(),
            Other(ref attr) => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::RouteMetricsNla::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            Lock(value)
                | Mtu(value)
                | Window(value)
                | Rtt(value)
                | RttVar(value)
                | SsThresh(value)
                | Cwnd(value)
                | Advmss(value)
                | Reordering(value)
                | Hoplimit(value)
                | InitCwnd(value)
                | Features(value)
                | RtoMin(value)
                | InitRwnd(value)
                | QuickAck(value)
                | CcAlgo(value)
                | FastopenNoCookie(value)
                => NativeEndian::write_u32(buffer, value),

            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::RouteMetricsNla::*;
        match *self {
            Unspec(_) => RTAX_UNSPEC,
            Lock(_) => RTAX_LOCK,
            Mtu(_) => RTAX_MTU,
            Window(_) => RTAX_WINDOW,
            Rtt(_) => RTAX_RTT,
            RttVar(_) => RTAX_RTTVAR,
            SsThresh(_) => RTAX_SSTHRESH,
            Cwnd(_) => RTAX_CWND,
            Advmss(_) => RTAX_ADVMSS,
            Reordering(_) => RTAX_REORDERING,
            Hoplimit(_) => RTAX_HOPLIMIT,
            InitCwnd(_) => RTAX_INITCWND,
            Features(_) => RTAX_FEATURES,
            RtoMin(_) => RTAX_RTO_MIN,
            InitRwnd(_) => RTAX_INITRWND,
            QuickAck(_) => RTAX_QUICKACK,
            CcAlgo(_) => RTAX_CC_ALGO,
            FastopenNoCookie(_) => RTAX_FASTOPEN_NO_COOKIE,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<RouteMetricsNla> for NlaBuffer<&'buffer T> {
    fn parse(&self) -> Result<RouteMetricsNla, DecodeError> {
        use self::RouteMetricsNla::*;
        let payload = self.value();
        Ok(match self.kind() {
            RTAX_UNSPEC => Unspec(payload.to_vec()),
            RTAX_LOCK => Lock(parse_u32(payload).context("invalid RTAX_LOCK value")?),
            RTAX_MTU => Mtu(parse_u32(payload).context("invalid RTAX_MTU value")?),
            RTAX_WINDOW => Window(parse_u32(payload).context("invalid RTAX_WINDOW value")?),
            RTAX_RTT => Rtt(parse_u32(payload).context("invalid RTAX_RTT value")?),
            RTAX_RTTVAR => RttVar(parse_u32(payload).context("invalid RTAX_RTTVAR value")?),
            RTAX_SSTHRESH => SsThresh(parse_u32(payload).context("invalid RTAX_SSTHRESH value")?),
            RTAX_CWND => Cwnd(parse_u32(payload).context("invalid RTAX_CWND value")?),
            RTAX_ADVMSS => Advmss(parse_u32(payload).context("invalid RTAX_ADVMSS value")?),
            RTAX_REORDERING => {
                Reordering(parse_u32(payload).context("invalid RTAX_REORDERING value")?)
            }
            RTAX_HOPLIMIT => Hoplimit(parse_u32(payload).context("invalid RTAX_HOPLIMIT value")?),
            RTAX_INITCWND => InitCwnd(parse_u32(payload).context("invalid RTAX_INITCWND value")?),
            RTAX_FEATURES => Features(parse_u32(payload).context("invalid RTAX_FEATURES value")?),
            RTAX_RTO_MIN => RtoMin(parse_u32(payload).context("invalid RTAX_RTO_MIN value")?),
            RTAX_INITRWND => InitRwnd(parse_u32(payload).context("invalid RTAX_INITRWND value")?),
            RTAX_QUICKACK => QuickAck(parse_u32(payload).context("invalid RTAX_QUICKACK value")?),
            RTAX_CC_ALGO => CcAlgo(parse_u32(payload).context("invalid RTAX_CC_ALGO value")?),
            RTAX_FASTOPEN_NO_COOKIE => FastopenNoCookie(
                parse_u32(payload).context("invalid RTAX_FASTOPEN_NO_COOKIE value")?,
            ),
            _ => Other(
                <Self as Parseable<DefaultNla>>::parse(self)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}
