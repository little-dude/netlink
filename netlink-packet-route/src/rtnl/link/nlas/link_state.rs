pub const IF_OPER_UNKNOWN: u8 = 0;
pub const IF_OPER_NOTPRESENT: u8 = 1;
pub const IF_OPER_DOWN: u8 = 2;
pub const IF_OPER_LOWERLAYERDOWN: u8 = 3;
pub const IF_OPER_TESTING: u8 = 4;
pub const IF_OPER_DORMANT: u8 = 5;
pub const IF_OPER_UP: u8 = 6;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LinkState {
    /// Status can't be determined
    Unknown,
    /// Some component is missing
    NotPresent,
    /// Down
    Down,
    /// Down due to state of lower layer
    LowerLayerDown,
    /// In some test mode
    Testing,
    /// Not up but pending an external event
    Dormant,
    /// Up, ready to send packets
    Up,
    /// Unrecognized value. This should go away when `TryFrom` is stable in Rust
    // FIXME: there's not point in having this. When TryFrom is stable we'll remove it
    Other(u8),
}

impl From<u8> for LinkState {
    fn from(value: u8) -> Self {
        use self::LinkState::*;
        match value {
            IF_OPER_UNKNOWN => Unknown,
            IF_OPER_NOTPRESENT => NotPresent,
            IF_OPER_DOWN => Down,
            IF_OPER_LOWERLAYERDOWN => LowerLayerDown,
            IF_OPER_TESTING => Testing,
            IF_OPER_DORMANT => Dormant,
            IF_OPER_UP => Up,
            _ => Other(value),
        }
    }
}

impl From<LinkState> for u8 {
    fn from(value: LinkState) -> Self {
        use self::LinkState::*;
        match value {
            Unknown => IF_OPER_UNKNOWN,
            NotPresent => IF_OPER_NOTPRESENT,
            Down => IF_OPER_DOWN,
            LowerLayerDown => IF_OPER_LOWERLAYERDOWN,
            Testing => IF_OPER_TESTING,
            Dormant => IF_OPER_DORMANT,
            Up => IF_OPER_UP,
            Other(other) => other,
        }
    }
}
