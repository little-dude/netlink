use crate::{
    constants::*,
    traits::{Emitable, Parseable},
    DecodeError, NeighbourMessageBuffer, NEIGHBOUR_HEADER_LEN,
};

/// Neighbour entry state
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum State {
    /// The neighbour has not (yet) been resolved
    Incomplete,
    /// The neighbour entry is valid until its lifetime expires
    Reachable,
    /// The neighbour entry is valid but suspicious
    Stale,
    /// The validation of this entry is currently delayed
    Delay,
    /// The neighbour entry is being probed
    Probe,
    /// The validation of this entry has failed
    Failed,

    /// Pseudo state for fresh entries or before deleting entries
    NoState,
    /// Entry is valid and the kernel will not try to validate or refresh it.
    NoARP,
    /// Entry is valid forever and can only be removed explicitly from userspace.
    Permanent,

    /// Catch-All to not fall into undefined behaviour
    Unknown(u16),
}

impl From<State> for u16 {
    fn from(value: State) -> u16 {
        use self::State::*;
        match value {
            Incomplete => NUD_INCOMPLETE,
            Reachable => NUD_REACHABLE,
            Stale => NUD_STALE,
            Delay => NUD_DELAY,
            Probe => NUD_PROBE,
            Failed => NUD_FAILED,
            NoARP => NUD_NOARP,
            Permanent => NUD_PERMANENT,
            NoState => NUD_NONE,
            Unknown(t) => t,
        }
    }
}

impl From<u16> for State {
    fn from(value: u16) -> State {
        use self::State::*;
        match value {
            NUD_INCOMPLETE => Incomplete,
            NUD_REACHABLE => Reachable,
            NUD_STALE => Stale,
            NUD_DELAY => Delay,
            NUD_PROBE => Probe,
            NUD_FAILED => Failed,
            NUD_NOARP => NoARP,
            NUD_PERMANENT => Permanent,
            NUD_NONE => NoState,
            _ => Unknown(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct Flags(u8);

impl From<u8> for Flags {
    fn from(value: u8) -> Self {
        Flags(value)
    }
}

impl From<Flags> for u8 {
    fn from(value: Flags) -> Self {
        value.0
    }
}

impl Default for Flags {
    fn default() -> Self {
        Flags::new()
    }
}

impl Flags {
    /// Create a new empty flag set
    pub fn new() -> Self {
        Flags(0)
    }

    pub fn has_use(self) -> bool {
        self.0 & NTF_USE == NTF_USE
    }

    pub fn set_use(&mut self) {
        self.0 |= NTF_USE
    }

    pub fn has_self(self) -> bool {
        self.0 & NTF_SELF == NTF_SELF
    }

    pub fn set_self(&mut self) {
        self.0 |= NTF_SELF
    }

    pub fn has_master(self) -> bool {
        self.0 & NTF_MASTER == NTF_MASTER
    }

    pub fn set_master(&mut self) {
        self.0 |= NTF_MASTER
    }

    pub fn has_proxy(self) -> bool {
        self.0 & NTF_PROXY == NTF_PROXY
    }

    pub fn set_proxy(&mut self) {
        self.0 |= NTF_PROXY
    }

    pub fn has_ext_learned(self) -> bool {
        self.0 & NTF_EXT_LEARNED == NTF_EXT_LEARNED
    }

    pub fn set_ext_learned(&mut self) {
        self.0 |= NTF_EXT_LEARNED
    }

    pub fn has_offloaded(self) -> bool {
        self.0 & NTF_OFFLOADED == NTF_OFFLOADED
    }

    pub fn set_offloaded(&mut self) {
        self.0 |= NTF_OFFLOADED
    }

    pub fn has_router(self) -> bool {
        self.0 & NTF_ROUTER == NTF_ROUTER
    }

    pub fn set_router(&mut self) {
        self.0 |= NTF_ROUTER
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourHeader {
    pub family: u8,
    pub ifindex: u32,
    pub state: State,
    pub flags: Flags,
    pub ntype: u8,
}

impl<T: AsRef<[u8]>> Parseable<NeighbourMessageBuffer<T>> for NeighbourHeader {
    fn parse(buf: &NeighbourMessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            family: buf.family(),
            ifindex: buf.ifindex(),
            state: buf.state().into(),
            flags: buf.flags().into(),
            ntype: buf.ntype(),
        })
    }
}

impl Emitable for NeighbourHeader {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = NeighbourMessageBuffer::new(buffer);
        packet.set_family(self.family);
        packet.set_ifindex(self.ifindex);
        packet.set_state(self.state.into());
        packet.set_flags(self.flags.into());
        packet.set_ntype(self.ntype);
    }
}
