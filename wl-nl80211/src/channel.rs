// SPDX-License-Identifier: MIT

const NL80211_CHAN_NO_HT: u32 = 0;
const NL80211_CHAN_HT20: u32 = 1;
const NL80211_CHAN_HT40MINUS: u32 = 2;
const NL80211_CHAN_HT40PLUS: u32 = 3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211WiPhyChannelType {
    NoHT,
    HT20,
    HT40Minus,
    HT40Plus,
    Other(u32),
}

impl From<u32> for Nl80211WiPhyChannelType {
    fn from(d: u32) -> Self {
        match d {
            NL80211_CHAN_NO_HT => Self::NoHT,
            NL80211_CHAN_HT20 => Self::HT20,
            NL80211_CHAN_HT40MINUS => Self::HT40Plus,
            NL80211_CHAN_HT40PLUS => Self::HT40Plus,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211WiPhyChannelType> for u32 {
    fn from(v: Nl80211WiPhyChannelType) -> u32 {
        match v {
            Nl80211WiPhyChannelType::NoHT => NL80211_CHAN_NO_HT,
            Nl80211WiPhyChannelType::HT20 => NL80211_CHAN_HT20,
            Nl80211WiPhyChannelType::HT40Minus => NL80211_CHAN_HT40MINUS,
            Nl80211WiPhyChannelType::HT40Plus => NL80211_CHAN_HT40PLUS,
            Nl80211WiPhyChannelType::Other(d) => d,
        }
    }
}

const NL80211_CHAN_WIDTH_20_NOHT: u32 = 0;
const NL80211_CHAN_WIDTH_20: u32 = 1;
const NL80211_CHAN_WIDTH_40: u32 = 2;
const NL80211_CHAN_WIDTH_80: u32 = 3;
const NL80211_CHAN_WIDTH_80P80: u32 = 4;
const NL80211_CHAN_WIDTH_160: u32 = 5;
const NL80211_CHAN_WIDTH_5: u32 = 6;
const NL80211_CHAN_WIDTH_10: u32 = 7;
const NL80211_CHAN_WIDTH_1: u32 = 8;
const NL80211_CHAN_WIDTH_2: u32 = 9;
const NL80211_CHAN_WIDTH_4: u32 = 10;
const NL80211_CHAN_WIDTH_8: u32 = 11;
const NL80211_CHAN_WIDTH_16: u32 = 12;
const NL80211_CHAN_WIDTH_320: u32 = 13;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211ChannelWidth {
    NoHt20,
    Mhz80Plus80,
    Mhz(u32),
    Other(u32),
}

impl From<u32> for Nl80211ChannelWidth {
    fn from(d: u32) -> Self {
        match d {
            NL80211_CHAN_WIDTH_20_NOHT => Self::NoHt20,
            NL80211_CHAN_WIDTH_20 => Self::Mhz(20),
            NL80211_CHAN_WIDTH_40 => Self::Mhz(40),
            NL80211_CHAN_WIDTH_80 => Self::Mhz(80),
            NL80211_CHAN_WIDTH_80P80 => Self::Mhz80Plus80,
            NL80211_CHAN_WIDTH_160 => Self::Mhz(160),
            NL80211_CHAN_WIDTH_5 => Self::Mhz(5),
            NL80211_CHAN_WIDTH_10 => Self::Mhz(10),
            NL80211_CHAN_WIDTH_1 => Self::Mhz(1),
            NL80211_CHAN_WIDTH_2 => Self::Mhz(2),
            NL80211_CHAN_WIDTH_4 => Self::Mhz(4),
            NL80211_CHAN_WIDTH_8 => Self::Mhz(8),
            NL80211_CHAN_WIDTH_16 => Self::Mhz(16),
            NL80211_CHAN_WIDTH_320 => Self::Mhz(320),
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211ChannelWidth> for u32 {
    fn from(v: Nl80211ChannelWidth) -> u32 {
        match v {
            Nl80211ChannelWidth::NoHt20 => NL80211_CHAN_WIDTH_20_NOHT,
            Nl80211ChannelWidth::Mhz(20) => NL80211_CHAN_WIDTH_20,
            Nl80211ChannelWidth::Mhz(40) => NL80211_CHAN_WIDTH_40,
            Nl80211ChannelWidth::Mhz(80) => NL80211_CHAN_WIDTH_80,
            Nl80211ChannelWidth::Mhz80Plus80 => NL80211_CHAN_WIDTH_80P80,
            Nl80211ChannelWidth::Mhz(160) => NL80211_CHAN_WIDTH_160,
            Nl80211ChannelWidth::Mhz(5) => NL80211_CHAN_WIDTH_5,
            Nl80211ChannelWidth::Mhz(10) => NL80211_CHAN_WIDTH_10,
            Nl80211ChannelWidth::Mhz(1) => NL80211_CHAN_WIDTH_1,
            Nl80211ChannelWidth::Mhz(2) => NL80211_CHAN_WIDTH_2,
            Nl80211ChannelWidth::Mhz(4) => NL80211_CHAN_WIDTH_4,
            Nl80211ChannelWidth::Mhz(8) => NL80211_CHAN_WIDTH_8,
            Nl80211ChannelWidth::Mhz(16) => NL80211_CHAN_WIDTH_16,
            Nl80211ChannelWidth::Mhz(320) => NL80211_CHAN_WIDTH_320,
            Nl80211ChannelWidth::Mhz(_) => {
                log::warn!("Invalid Nl80211ChannelWidth {:?}", v);
                u32::MAX
            }
            Nl80211ChannelWidth::Other(d) => d,
        }
    }
}
