use crate::constants::*;
use failure::ResultExt;

use crate::{
    AddressBuffer, AddressMessage, DecodeError, Emitable, LinkBuffer, LinkMessage, NeighbourBuffer,
    NeighbourMessage, NeighbourTableBuffer, NeighbourTableMessage, Parseable,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RtnlMessage {
    NewLink(LinkMessage),
    DelLink(LinkMessage),
    GetLink(LinkMessage),
    SetLink(LinkMessage),
    NewAddress(AddressMessage),
    DelAddress(AddressMessage),
    GetAddress(AddressMessage),
    NewNeighbour(NeighbourMessage),
    GetNeighbour(NeighbourMessage),
    DelNeighbour(NeighbourMessage),
    NewNeighbourTable(NeighbourTableMessage),
    GetNeighbourTable(NeighbourTableMessage),
    SetNeighbourTable(NeighbourTableMessage),
}

impl RtnlMessage {
    pub fn is_new_link(&self) -> bool {
        if let RtnlMessage::NewLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_link(&self) -> bool {
        if let RtnlMessage::DelLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_link(&self) -> bool {
        if let RtnlMessage::GetLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_set_link(&self) -> bool {
        if let RtnlMessage::SetLink(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_address(&self) -> bool {
        if let RtnlMessage::NewAddress(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_address(&self) -> bool {
        if let RtnlMessage::DelAddress(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_address(&self) -> bool {
        if let RtnlMessage::GetAddress(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_neighbour(&self) -> bool {
        if let RtnlMessage::GetNeighbour(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_neighbour(&self) -> bool {
        if let RtnlMessage::NewNeighbour(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_neighbour(&self) -> bool {
        if let RtnlMessage::DelNeighbour(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_neighbour_table(&self) -> bool {
        if let RtnlMessage::NewNeighbourTable(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_neighbour_table(&self) -> bool {
        if let RtnlMessage::GetNeighbourTable(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_set_neighbour_table(&self) -> bool {
        if let RtnlMessage::SetNeighbourTable(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn message_type(&self) -> u16 {
        use self::RtnlMessage::*;

        match self {
            NewLink(_) => RTM_NEWLINK,
            DelLink(_) => RTM_DELLINK,
            GetLink(_) => RTM_GETLINK,
            SetLink(_) => RTM_SETLINK,
            NewAddress(_) => RTM_NEWADDR,
            DelAddress(_) => RTM_DELADDR,
            GetAddress(_) => RTM_GETADDR,
            GetNeighbour(_) => RTM_GETNEIGH,
            NewNeighbour(_) => RTM_NEWNEIGH,
            DelNeighbour(_) => RTM_DELNEIGH,
            GetNeighbourTable(_) => RTM_GETNEIGHTBL,
            NewNeighbourTable(_) => RTM_NEWNEIGHTBL,
            SetNeighbourTable(_) => RTM_SETNEIGHTBL,
        }
    }

    pub(crate) fn parse(message_type: u16, buffer: &[u8]) -> Result<Self, DecodeError> {
        use self::RtnlMessage::*;
        let message = match message_type {
            // Link messages
            RTM_NEWLINK | RTM_GETLINK | RTM_DELLINK | RTM_SETLINK => {
                let msg: LinkMessage = LinkBuffer::new(&buffer)
                    .parse()
                    .context("invalid link message")?;
                match message_type {
                    RTM_NEWLINK => NewLink(msg),
                    RTM_GETLINK => GetLink(msg),
                    RTM_DELLINK => DelLink(msg),
                    RTM_SETLINK => SetLink(msg),
                    _ => unreachable!(),
                }
            }
            // Address messages
            RTM_NEWADDR | RTM_GETADDR | RTM_DELADDR => {
                let msg: AddressMessage = AddressBuffer::new(&buffer)
                    .parse()
                    .context("invalid address message")?;
                match message_type {
                    RTM_NEWADDR => NewAddress(msg),
                    RTM_GETADDR => GetAddress(msg),
                    RTM_DELADDR => DelAddress(msg),
                    _ => unreachable!(),
                }
            }
            // Neighbour messages
            RTM_NEWNEIGH | RTM_GETNEIGH | RTM_DELNEIGH => {
                let msg: NeighbourMessage = NeighbourBuffer::new(&buffer)
                    .parse()
                    .context("invalid neighbour message")?;
                match message_type {
                    RTM_GETNEIGH => GetNeighbour(msg),
                    RTM_NEWNEIGH => NewNeighbour(msg),
                    RTM_DELNEIGH => DelNeighbour(msg),
                    _ => unreachable!(),
                }
            }
            // Neighbour table messages
            RTM_NEWNEIGHTBL | RTM_GETNEIGHTBL | RTM_SETNEIGHTBL => {
                let msg: NeighbourTableMessage = NeighbourTableBuffer::new(&buffer)
                    .parse()
                    .context("invalid neighbour table message")?;
                match message_type {
                    RTM_GETNEIGHTBL => GetNeighbourTable(msg),
                    RTM_NEWNEIGHTBL => NewNeighbourTable(msg),
                    RTM_SETNEIGHTBL => SetNeighbourTable(msg),
                    _ => unreachable!(),
                }
            }
            _ => return Err(format!("Unknown message type: {}", message_type).into()),
        };
        Ok(message)
    }
}

impl Emitable for RtnlMessage {
    #[rustfmt::skip]
    fn buffer_len(&self) -> usize {
        use self::RtnlMessage::*;
        match self {
            | NewLink(ref msg)
            | DelLink(ref msg)
            | GetLink(ref msg)
            | SetLink(ref msg)
            =>  msg.buffer_len(),

            | NewAddress(ref msg)
            | DelAddress(ref msg)
            | GetAddress(ref msg)
            => msg.buffer_len(),

            | NewNeighbour(ref msg)
            | GetNeighbour(ref msg)
            | DelNeighbour(ref msg)
            => msg.buffer_len(),

            | NewNeighbourTable(ref msg)
            | GetNeighbourTable(ref msg)
            | SetNeighbourTable(ref msg)
            => msg.buffer_len(),
        }
    }

    #[rustfmt::skip]
    fn emit(&self, buffer: &mut [u8]) {
        use self::RtnlMessage::*;
        match self {
            | NewLink(ref msg)
            | DelLink(ref msg)
            | GetLink(ref msg)
            | SetLink(ref msg)
            => msg.emit(buffer),

            | NewAddress(ref msg)
            | DelAddress(ref msg)
            | GetAddress(ref msg)
            => msg.emit(buffer),

            | GetNeighbour(ref msg)
            | NewNeighbour(ref msg)
            | DelNeighbour(ref msg)
            => msg.emit(buffer),

            | GetNeighbourTable(ref msg)
            | NewNeighbourTable(ref msg)
            | SetNeighbourTable(ref msg)
            => msg.emit(buffer),
        }
    }
}
