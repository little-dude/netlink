use crate::constants::*;
use failure::ResultExt;

use crate::{
    AddressBuffer, AddressHeader, AddressMessage, DecodeError, Emitable, LinkBuffer, LinkHeader,
    LinkMessage, NeighbourBuffer, NeighbourMessage, NeighbourTableBuffer, NeighbourTableMessage,
    Parseable, RouteBuffer, RouteHeader, RouteMessage, TcBuffer, TcMessage,
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
    NewRoute(RouteMessage),
    DelRoute(RouteMessage),
    GetRoute(RouteMessage),
    NewQueueDiscipline(TcMessage),
    DelQueueDiscipline(TcMessage),
    GetQueueDiscipline(TcMessage),
    NewTrafficClass(TcMessage),
    DelTrafficClass(TcMessage),
    GetTrafficClass(TcMessage),
    NewTrafficFilter(TcMessage),
    DelTrafficFilter(TcMessage),
    GetTrafficFilter(TcMessage),
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

    pub fn is_new_route(&self) -> bool {
        if let RtnlMessage::NewRoute(_) = *self {
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

    pub fn is_get_route(&self) -> bool {
        if let RtnlMessage::GetRoute(_) = *self {
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

    pub fn is_del_route(&self) -> bool {
        if let RtnlMessage::DelRoute(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_qdisc(&self) -> bool {
        if let RtnlMessage::NewQueueDiscipline(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_qdisc(&self) -> bool {
        if let RtnlMessage::DelQueueDiscipline(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_qdisc(&self) -> bool {
        if let RtnlMessage::GetQueueDiscipline(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_class(&self) -> bool {
        if let RtnlMessage::NewTrafficClass(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_class(&self) -> bool {
        if let RtnlMessage::DelTrafficClass(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_class(&self) -> bool {
        if let RtnlMessage::GetTrafficClass(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_filter(&self) -> bool {
        if let RtnlMessage::NewTrafficFilter(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_filter(&self) -> bool {
        if let RtnlMessage::DelTrafficFilter(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_filter(&self) -> bool {
        if let RtnlMessage::GetTrafficFilter(_) = *self {
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
            NewRoute(_) => RTM_NEWROUTE,
            DelRoute(_) => RTM_DELROUTE,
            GetRoute(_) => RTM_GETROUTE,
            NewQueueDiscipline(_) => RTM_NEWQDISC,
            DelQueueDiscipline(_) => RTM_DELQDISC,
            GetQueueDiscipline(_) => RTM_GETQDISC,
            NewTrafficClass(_) => RTM_NEWTCLASS,
            DelTrafficClass(_) => RTM_DELTCLASS,
            GetTrafficClass(_) => RTM_GETTCLASS,
            NewTrafficFilter(_) => RTM_NEWTFILTER,
            DelTrafficFilter(_) => RTM_DELTFILTER,
            GetTrafficFilter(_) => RTM_GETTFILTER,
        }
    }

    #[rustfmt::skip]
    pub(crate) fn parse(message_type: u16, buffer: &[u8]) -> Result<Self, DecodeError> {
        use self::RtnlMessage::*;
        let message = match message_type {

            // Link messages
            RTM_NEWLINK | RTM_GETLINK | RTM_DELLINK | RTM_SETLINK => {
                let msg: LinkMessage = match LinkBuffer::new_checked(&buffer) {
                    Ok(buf) => buf.parse().context("invalid link message")?,
                    // HACK: iproute2 sends invalid RTM_GETLINK message, where the header is
                    // limited to the interface family (1 byte) and 3 bytes of padding.
                    Err(e) => {
                        if buffer.len() == 4 && message_type == RTM_GETLINK {
                            let mut msg = LinkMessage {
                                header: LinkHeader::new(),
                                nlas: vec![],
                            };
                            msg.header.interface_family = buffer[0];
                            msg
                        } else {
                            return Err(e);
                        }
                    }
                };
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
                let msg: AddressMessage = match AddressBuffer::new_checked(&buffer) {
                    Ok(buf) => buf.parse().context("invalid link message")?,
                    // HACK: iproute2 sends invalid RTM_GETADDR message, where the header is
                    // limited to the interface family (1 byte) and 3 bytes of padding.
                    Err(e) => {
                        if buffer.len() == 4 && message_type == RTM_GETADDR {
                            let mut msg = AddressMessage {
                                header: AddressHeader::new(),
                                nlas: vec![],
                            };
                            msg.header.family = buffer[0];
                            msg
                        } else {
                            return Err(e);
                        }
                    }
                };
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

            // Route messages
            RTM_NEWROUTE | RTM_GETROUTE | RTM_DELROUTE => {
                let msg: RouteMessage = match RouteBuffer::new_checked(&buffer) {
                    Ok(buf) => buf.parse().context("invalid route message")?,
                    // HACK: iproute2 sends invalid RTM_GETROUTE message, where the header is
                    // limited to the interface family (1 byte) and 3 bytes of padding.
                    Err(e) => {
                        if buffer.len() == 4 && message_type == RTM_GETROUTE {
                            let mut msg = RouteMessage {
                                header: RouteHeader::new(),
                                nlas: vec![],
                            };
                            msg.header.address_family = buffer[0];
                            msg
                        } else {
                            return Err(e);
                        }
                    }
                };
                match message_type {
                    RTM_NEWROUTE => NewRoute(msg),
                    RTM_GETROUTE => GetRoute(msg),
                    RTM_DELROUTE => DelRoute(msg),
                    _ => unreachable!(),
                }
            }

            // TC Messages
            RTM_NEWQDISC | RTM_DELQDISC | RTM_GETQDISC |
            RTM_NEWTCLASS | RTM_DELTCLASS | RTM_GETTCLASS |
            RTM_NEWTFILTER | RTM_DELTFILTER | RTM_GETTFILTER => {
                let msg: TcMessage = TcBuffer::new(&buffer)
                    .parse()
                    .context("invalid tc message")?;
                match message_type {
                    RTM_NEWQDISC => NewQueueDiscipline(msg),
                    RTM_DELQDISC => DelQueueDiscipline(msg),
                    RTM_GETQDISC => GetQueueDiscipline(msg),
                    RTM_NEWTCLASS => NewTrafficClass(msg),
                    RTM_DELTCLASS => DelTrafficClass(msg),
                    RTM_GETTCLASS => GetTrafficClass(msg),
                    RTM_NEWTFILTER => NewTrafficFilter(msg),
                    RTM_DELTFILTER => DelTrafficFilter(msg),
                    RTM_GETTFILTER => GetTrafficFilter(msg),
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

            | NewRoute(ref msg)
            | DelRoute(ref msg)
            | GetRoute(ref msg)
            => msg.buffer_len(),

            | NewQueueDiscipline(ref msg)
            | DelQueueDiscipline(ref msg)
            | GetQueueDiscipline(ref msg)
            | NewTrafficClass(ref msg)
            | DelTrafficClass(ref msg)
            | GetTrafficClass(ref msg)
            | NewTrafficFilter(ref msg)
            | DelTrafficFilter(ref msg)
            | GetTrafficFilter(ref msg)
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
            => msg.emit(buffer),

            | GetNeighbour(ref msg)
            | NewNeighbour(ref msg)
            | DelNeighbour(ref msg)
            => msg.emit(buffer),

            | GetNeighbourTable(ref msg)
            | NewNeighbourTable(ref msg)
            | SetNeighbourTable(ref msg)
            => msg.emit(buffer),

            | NewRoute(ref msg)
            | DelRoute(ref msg)
            | GetRoute(ref msg)
            => msg.emit(buffer),

            | NewQueueDiscipline(ref msg)
            | DelQueueDiscipline(ref msg)
            | GetQueueDiscipline(ref msg)
            | NewTrafficClass(ref msg)
            | DelTrafficClass(ref msg)
            | GetTrafficClass(ref msg)
            | NewTrafficFilter(ref msg)
            | DelTrafficFilter(ref msg)
            | GetTrafficFilter(ref msg)
            => msg.emit(buffer)
        }
    }
}
