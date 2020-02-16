use failure::{Compat as FailureError, Fail};

use crate::{
    constants::*,
    traits::{Emitable, ParseableParametrized},
    AddressMessage, DecodeError, LinkMessage, NeighbourMessage, NeighbourTableMessage,
    NetlinkDeserializable, NetlinkHeader, NetlinkPayload, NetlinkSerializable, NsidMessage,
    RouteMessage, RtnlMessageBuffer, RuleMessage, TcMessage,
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
    NewNsId(NsidMessage),
    DelNsId(NsidMessage),
    GetNsId(NsidMessage),
    NewRule(RuleMessage),
    DelRule(RuleMessage),
    GetRule(RuleMessage),
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

    pub fn is_new_nsid(&self) -> bool {
        if let RtnlMessage::NewNsId(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_nsid(&self) -> bool {
        if let RtnlMessage::GetNsId(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_nsid(&self) -> bool {
        if let RtnlMessage::DelNsId(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_get_rule(&self) -> bool {
        if let RtnlMessage::GetRule(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_new_rule(&self) -> bool {
        if let RtnlMessage::NewRule(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_rule(&self) -> bool {
        if let RtnlMessage::DelRule(_) = *self {
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
            GetNsId(_) => RTM_GETNSID,
            NewNsId(_) => RTM_NEWNSID,
            DelNsId(_) => RTM_DELNSID,
            GetRule(_) => RTM_GETRULE,
            NewRule(_) => RTM_NEWRULE,
            DelRule(_) => RTM_DELRULE,
        }
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
            => msg.buffer_len(),

            | NewNsId(ref msg)
            | DelNsId(ref msg)
            | GetNsId(ref msg)
            => msg.buffer_len(),

            | NewRule(ref msg)
            | DelRule(ref msg)
            | GetRule(ref msg)
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
            => msg.emit(buffer),

            | NewNsId(ref msg)
            | DelNsId(ref msg)
            | GetNsId(ref msg)
            => msg.emit(buffer),

            | NewRule(ref msg)
            | DelRule(ref msg)
            | GetRule(ref msg)
            => msg.emit(buffer)
        }
    }
}

impl NetlinkSerializable<RtnlMessage> for RtnlMessage {
    fn message_type(&self) -> u16 {
        self.message_type()
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable<RtnlMessage> for RtnlMessage {
    type Error = FailureError<DecodeError>;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        let buf = RtnlMessageBuffer::new(payload);
        match RtnlMessage::parse_with_param(&buf, header.message_type) {
            Err(e) => Err(e.compat()),
            Ok(message) => Ok(message),
        }
    }
}

impl From<RtnlMessage> for NetlinkPayload<RtnlMessage> {
    fn from(message: RtnlMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
