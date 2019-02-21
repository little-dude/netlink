use std::str::FromStr;

use failure::{bail, Error};

use crate::sock_diag::SkMemInfo;
use crate::{
    sock_diag::{buffer::CStruct, sock::State},
    TcpStates, UnixStates,
};

impl CStruct for SkMemInfo {}

use State::*;

bitflags! {
    pub struct States: u32 {
        const UNKNOWN       = 1 << SS_UNKNOWN as u8;
        const ESTABLISHED   = 1 << SS_ESTABLISHED as u8;
        const SYN_SENT      = 1 << SS_SYN_SENT as u8;
        const SYN_RECV      = 1 << SS_SYN_RECV as u8;
        const FIN_WAIT1     = 1 << SS_FIN_WAIT1 as u8;
        const FIN_WAIT2     = 1 << SS_FIN_WAIT2 as u8;
        const TIME_WAIT     = 1 << SS_TIME_WAIT as u8;
        const CLOSE         = 1 << SS_CLOSE as u8;
        const CLOSE_WAIT    = 1 << SS_CLOSE_WAIT as u8;
        const LAST_ACK      = 1 << SS_LAST_ACK as u8;
        const LISTEN        = 1 << SS_LISTEN as u8;
        const CLOSING       = 1 << SS_CLOSING as u8;
    }
}

impl States {
    pub fn conn() -> Self {
        let mut states = Self::all();
        states.remove(Self::LISTEN | Self::CLOSE | Self::TIME_WAIT | Self::SYN_RECV);
        states
    }

    /// all the states except for `listening` and `closed`
    pub fn connected() -> Self {
        let mut states = Self::all();
        states.remove(Self::LISTEN | Self::CLOSE);
        states
    }

    /// all the connected states except for `syn-sent`
    pub fn synchronized() -> Self {
        let mut states = Self::connected();
        states.remove(Self::SYN_SENT);
        states
    }

    /// states, which are maintained as minisockets, i.e. `time-wait` and `syn-recv`
    pub fn bucket() -> Self {
        Self::SYN_RECV | Self::TIME_WAIT
    }

    /// opposite to bucket
    pub fn big() -> Self {
        let mut states = Self::all();
        states.remove(Self::bucket());
        states
    }

    pub fn len(&self) -> usize {
        self.bits.count_ones() as usize
    }
}

impl FromStr for States {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let states = match s {
            "established" => Self::ESTABLISHED,
            "syn-sent" => Self::SYN_SENT,
            "syn-recv" | "syn-rcv" => Self::SYN_RECV,
            "fin-wait-1" => Self::FIN_WAIT1,
            "fin-wait-2" => Self::FIN_WAIT2,
            "time-wait" => Self::TIME_WAIT,
            "close" | "closed" => Self::CLOSE,
            "close-wait" => Self::CLOSE_WAIT,
            "last-ack" => Self::LAST_ACK,
            "listening" | "listen" => Self::LISTEN,
            "closing" => Self::CLOSING,

            "all" => Self::all(),
            "connected" => Self::connected(),
            "synchronized" => Self::synchronized(),
            "bucket" => Self::bucket(),
            "big" => Self::big(),

            _ => bail!("wrong state name {}", s),
        };

        Ok(states)
    }
}

impl From<States> for TcpStates {
    fn from(states: States) -> Self {
        TcpStates::from_bits_truncate(states.bits)
    }
}

impl From<States> for UnixStates {
    fn from(states: States) -> Self {
        UnixStates::from_bits_truncate(states.bits)
    }
}
