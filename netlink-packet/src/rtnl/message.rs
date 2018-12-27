use constants::*;
use failure::ResultExt;

use {AddressBuffer, AddressMessage, DecodeError, Emitable, LinkBuffer, LinkMessage, Parseable};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RtnlMessage {
    NewLink(LinkMessage),
    DelLink(LinkMessage),
    GetLink(LinkMessage),
    SetLink(LinkMessage),
    NewAddress(AddressMessage),
    DelAddress(AddressMessage),
    GetAddress(AddressMessage),
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
            => msg.buffer_len()
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
            => msg.emit(buffer)
        }
    }
}
