use packet::constants::message_type::*;

/// Represent the message type field in a netlink packet header
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum NetlinkMessageType {
    /// The message type is `NLMSG_NOOP`: the message is ignored.
    Noop,
    /// The message type is `NLMSG_ERROR`. The message signals an error and the payload contains a
    /// nlmsgerr structure. This can be looked at as a NACK and typically it is from FEC to CPC.
    Error,
    /// The message type is `NLMSG_DONE`: the message terminates a multipart message.
    Done,
    /// The message type is `NLMSG_OVERRUN`: data lost
    Overrun,
    /// The message type is `RTM_NEWLINK`
    NewLink,
    /// The message type is `RTM_DELLINK`
    DelLink,
    /// The message type is `RTM_GETLINK`
    GetLink,
    /// The message type is `RTM_SETLINK`
    SetLink,
    /// The message type is `RTM_NEWADDR`
    NewAddress,
    /// The message type is `RTM_DELADDR`
    DelAddress,
    /// The message type is `RTM_GETADDR`
    GetAddress,
    /// The message type is `RTM_NEWROUTE`
    NewRoute,
    /// The message type is `RTM_DELROUTE`
    DelRoute,
    /// The message type is `RTM_GETROUTE`
    GetRoute,
    /// The message type is `RTM_NEWNEIGH`
    NewNeighbour,
    /// The message type is `RTM_DELNEIGH`
    DelNeighbour,
    /// The message type is `RTM_GETNEIGH`
    GetNeighbour,
    /// The message type is `RTM_NEWRULE`
    NewRule,
    /// The message type is `RTM_DELRULE`
    DelRule,
    /// The message type is `RTM_GETRULE`
    GetRule,
    /// The message type is `RTM_NEWQDISC`
    NewQueueDiscipline,
    /// The message type is `RTM_DELQDISC`
    DelQueueDiscipline,
    /// The message type is `RTM_GETQDISC`
    GetQueueDiscipline,
    /// The message type is `RTM_NEWTCLASS`
    NewTrafficClass,
    /// The message type is `RTM_DELTCLASS`
    DelTrafficClass,
    /// The message type is `RTM_GETTCLASS`
    GetTrafficClass,
    /// The message type is `RTM_NEWTFILTER`
    NewTrafficFilter,
    /// The message type is `RTM_DELTFILTER`
    DelTrafficFilter,
    /// The message type is `RTM_GETTFILTER`
    GetTrafficFilter,
    /// The message type is `RTM_NEWACTION`
    NewAction,
    /// The message type is `RTM_DELACTION`
    DelAction,
    /// The message type is `RTM_GETACTION`
    GetAction,
    /// The message type is `RTM_NEWPREFIX`
    NewPrefix,
    /// The message type is `RTM_GETMULTICAST`
    GetMulticast,
    /// The message type is `RTM_GETANYCAST`
    GetAnycast,
    /// The message type is `RTM_NEWNEIGHTBL`
    NewNeighbourTable,
    /// The message type is `RTM_SETNEIGHTBL`
    SetNeighbourTable,
    /// The message type is `RTM_GETNEIGHTBL`
    GetNeighbourTable,
    /// The message type is `RTM_NEWNDUSEROPT`
    NewNeighbourDiscoveryUserOption,
    /// The message type is `RTM_NEWADDRLABEL`
    NewAddressLabel,
    /// The message type is `RTM_DELADDRLABEL`
    DelAddressLabel,
    /// The message type is `RTM_GETADDRLABEL`
    GetAddressLabel,
    /// The message type is `RTM_GETDCB`
    GetDcb,
    /// The message type is `RTM_SETDCB`
    SetDcb,
    /// The message type is `RTM_NEWNETCONF`
    NewNetconf,
    /// The message type is `RTM_DELNETCONF`
    DelNetconf,
    /// The message type is `RTM_GETNETCONF`
    GetNetconf,
    /// The message type is `RTM_NEWMDB`
    NewMdb,
    /// The message type is `RTM_DELMDB`
    DelMdb,
    /// The message type is `RTM_GETMDB`
    GetMdb,
    /// The message type is `RTM_NEWNSID`
    NewNsId,
    /// The message type is `RTM_DELNSID`
    DelNsId,
    /// The message type is `RTM_GETNSID`
    GetNsId,
    /// The message type is `RTM_NEWSTATS`
    NewStats,
    /// The message type is `RTM_GETSTATS`
    GetStats,
    /// The message type is `RTM_NEWCACHEREPORT`
    NewCacheReport,
    Other(u16),
}

impl From<u16> for NetlinkMessageType {
    fn from(value: u16) -> Self {
        use self::NetlinkMessageType::*;
        match value {
            NLMSG_NOOP => Noop,
            NLMSG_ERROR => Error,
            NLMSG_DONE => Done,
            NLMSG_OVERRUN => Overrun,
            RTM_NEWLINK => NewLink,
            RTM_DELLINK => DelLink,
            RTM_GETLINK => GetLink,
            RTM_SETLINK => SetLink,
            RTM_NEWADDR => NewAddress,
            RTM_DELADDR => DelAddress,
            RTM_GETADDR => GetAddress,
            RTM_NEWROUTE => NewRoute,
            RTM_DELROUTE => DelRoute,
            RTM_GETROUTE => GetRoute,
            RTM_NEWNEIGH => NewNeighbour,
            RTM_DELNEIGH => DelNeighbour,
            RTM_GETNEIGH => GetNeighbour,
            RTM_NEWRULE => NewRule,
            RTM_DELRULE => DelRule,
            RTM_GETRULE => GetRule,
            RTM_NEWQDISC => NewQueueDiscipline,
            RTM_DELQDISC => DelQueueDiscipline,
            RTM_GETQDISC => GetQueueDiscipline,
            RTM_NEWTCLASS => NewTrafficClass,
            RTM_DELTCLASS => DelTrafficClass,
            RTM_GETTCLASS => GetTrafficClass,
            RTM_NEWTFILTER => NewTrafficFilter,
            RTM_DELTFILTER => DelTrafficFilter,
            RTM_GETTFILTER => GetTrafficFilter,
            RTM_NEWACTION => NewAction,
            RTM_DELACTION => DelAction,
            RTM_GETACTION => GetAction,
            RTM_NEWPREFIX => NewPrefix,
            RTM_GETMULTICAST => GetMulticast,
            RTM_GETANYCAST => GetAnycast,
            RTM_NEWNEIGHTBL => NewNeighbourTable,
            RTM_SETNEIGHTBL => SetNeighbourTable,
            RTM_GETNEIGHTBL => GetNeighbourTable,
            RTM_NEWNDUSEROPT => NewNeighbourDiscoveryUserOption,
            RTM_NEWADDRLABEL => NewAddressLabel,
            RTM_DELADDRLABEL => DelAddressLabel,
            RTM_GETADDRLABEL => GetAddressLabel,
            RTM_GETDCB => GetDcb,
            RTM_SETDCB => SetDcb,
            RTM_NEWNETCONF => NewNetconf,
            RTM_DELNETCONF => DelNetconf,
            RTM_GETNETCONF => GetNetconf,
            RTM_NEWMDB => NewMdb,
            RTM_DELMDB => DelMdb,
            RTM_GETMDB => GetMdb,
            RTM_NEWNSID => NewNsId,
            RTM_DELNSID => DelNsId,
            RTM_GETNSID => GetNsId,
            RTM_NEWSTATS => NewStats,
            RTM_GETSTATS => GetStats,
            RTM_NEWCACHEREPORT => NewCacheReport,
            _ => Other(value),
        }
    }
}

impl Into<u16> for NetlinkMessageType {
    fn into(self) -> u16 {
        use self::NetlinkMessageType::*;
        match self {
            Noop => NLMSG_NOOP,
            Error => NLMSG_ERROR,
            Done => NLMSG_DONE,
            Overrun => NLMSG_OVERRUN,
            NewLink => RTM_NEWLINK,
            DelLink => RTM_DELLINK,
            GetLink => RTM_GETLINK,
            SetLink => RTM_SETLINK,
            NewAddress => RTM_NEWADDR,
            DelAddress => RTM_DELADDR,
            GetAddress => RTM_GETADDR,
            NewRoute => RTM_NEWROUTE,
            DelRoute => RTM_DELROUTE,
            GetRoute => RTM_GETROUTE,
            NewNeighbour => RTM_NEWNEIGH,
            DelNeighbour => RTM_DELNEIGH,
            GetNeighbour => RTM_GETNEIGH,
            NewRule => RTM_NEWRULE,
            DelRule => RTM_DELRULE,
            GetRule => RTM_GETRULE,
            NewQueueDiscipline => RTM_NEWQDISC,
            DelQueueDiscipline => RTM_DELQDISC,
            GetQueueDiscipline => RTM_GETQDISC,
            NewTrafficClass => RTM_NEWTCLASS,
            DelTrafficClass => RTM_DELTCLASS,
            GetTrafficClass => RTM_GETTCLASS,
            NewTrafficFilter => RTM_NEWTFILTER,
            DelTrafficFilter => RTM_DELTFILTER,
            GetTrafficFilter => RTM_GETTFILTER,
            NewAction => RTM_NEWACTION,
            DelAction => RTM_DELACTION,
            GetAction => RTM_GETACTION,
            NewPrefix => RTM_NEWPREFIX,
            GetMulticast => RTM_GETMULTICAST,
            GetAnycast => RTM_GETANYCAST,
            NewNeighbourTable => RTM_NEWNEIGHTBL,
            SetNeighbourTable => RTM_SETNEIGHTBL,
            GetNeighbourTable => RTM_GETNEIGHTBL,
            NewNeighbourDiscoveryUserOption => RTM_NEWNDUSEROPT,
            NewAddressLabel => RTM_NEWADDRLABEL,
            DelAddressLabel => RTM_DELADDRLABEL,
            GetAddressLabel => RTM_GETADDRLABEL,
            GetDcb => RTM_GETDCB,
            SetDcb => RTM_SETDCB,
            NewNetconf => RTM_NEWNETCONF,
            DelNetconf => RTM_DELNETCONF,
            GetNetconf => RTM_GETNETCONF,
            NewMdb => RTM_NEWMDB,
            DelMdb => RTM_DELMDB,
            GetMdb => RTM_GETMDB,
            NewNsId => RTM_NEWNSID,
            DelNsId => RTM_DELNSID,
            GetNsId => RTM_GETNSID,
            NewStats => RTM_NEWSTATS,
            GetStats => RTM_GETSTATS,
            NewCacheReport => RTM_NEWCACHEREPORT,
            Other(v) => v,
        }
    }
}
