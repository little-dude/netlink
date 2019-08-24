use crate::{
    rtnl::{
        address::{AddressBuffer, AddressHeader, AddressMessage},
        link::{LinkBuffer, LinkHeader, LinkMessage},
        message_types::*,
        neighbour::{NeighbourBuffer, NeighbourMessage},
        neighbour_table::{NeighbourTableBuffer, NeighbourTableMessage},
        nsid::{NsIdBuffer, NsIdMessage},
        route::{RouteBuffer, RouteHeader, RouteMessage},
        tc::{TcBuffer, TcMessage},
        traits::{Parseable, ParseableParametrized},
        RtnlMessage,
    },
    DecodeError,
};
use failure::ResultExt;

pub struct RtnlBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RtnlBuffer<T> {
    pub fn new(buffer: T) -> RtnlBuffer<T> {
        RtnlBuffer { buffer }
    }

    pub fn length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    pub fn new_checked(buffer: T) -> Result<RtnlBuffer<T>, DecodeError> {
        Ok(Self::new(buffer))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> RtnlBuffer<&'a T> {
    pub fn inner(&self) -> &'a [u8] {
        &self.buffer.as_ref()[..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> RtnlBuffer<&'a mut T> {
    pub fn inner_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..]
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> ParseableParametrized<RtnlMessage, u16>
    for RtnlBuffer<&'buffer T>
{
    #[rustfmt::skip]
    fn parse_with_param(&self, message_type: u16) -> Result<RtnlMessage, DecodeError> {
        use self::RtnlMessage::*;
        let message = match message_type {

            // Link messages
            RTM_NEWLINK | RTM_GETLINK | RTM_DELLINK | RTM_SETLINK => {
                let msg: LinkMessage = match LinkBuffer::new_checked(&self.inner()) {
                    Ok(buf) => buf.parse().context("invalid link message")?,
                    // HACK: iproute2 sends invalid RTM_GETLINK message, where the header is
                    // limited to the interface family (1 byte) and 3 bytes of padding.
                    Err(e) => {
                        if self.length() == 4 && message_type == RTM_GETLINK {
                            let mut msg = LinkMessage {
                                header: LinkHeader::new(),
                                nlas: vec![],
                            };
                            msg.header.interface_family = self.inner()[0];
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
                let msg: AddressMessage = match AddressBuffer::new_checked(&self.inner()) {
                    Ok(buf) => buf.parse().context("invalid link message")?,
                    // HACK: iproute2 sends invalid RTM_GETADDR message, where the header is
                    // limited to the interface family (1 byte) and 3 bytes of padding.
                    Err(e) => {
                        if self.length() == 4 && message_type == RTM_GETADDR {
                            let mut msg = AddressMessage {
                                header: AddressHeader::new(),
                                nlas: vec![],
                            };
                            msg.header.family = self.inner()[0];
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
                let msg: NeighbourMessage = NeighbourBuffer::new_checked(&self.inner())
                    .context("invalid neighbour message")?
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
                let msg: NeighbourTableMessage = NeighbourTableBuffer::new_checked(&self.inner())
                    .context("invalid neighbour table message")?
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
                let msg: RouteMessage = match RouteBuffer::new_checked(&self.inner()) {
                    Ok(buf) => buf.parse().context("invalid route message")?,
                    // HACK: iproute2 sends invalid RTM_GETROUTE message, where the header is
                    // limited to the interface family (1 byte) and 3 bytes of padding.
                    Err(e) => {
                        // Not only does iproute2 sends invalid messages, it's also inconsistent in
                        // doing so: for link and address messages, the length advertised in the
                        // netlink header includes the 3 bytes of padding but it does not seem to
                        // be the case for the route message, hence the self.length() == 1 check.
                        if (self.length() == 4 || self.length() == 1) && message_type == RTM_GETROUTE {
                            let mut msg = RouteMessage {
                                header: RouteHeader::new(),
                                nlas: vec![],
                            };
                            msg.header.address_family = self.inner()[0];
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
                let msg: TcMessage = TcBuffer::new_checked(&self.inner())
                    .context("invalid tc message")?
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

            // ND ID Messages
            RTM_NEWNSID | RTM_GETNSID | RTM_DELNSID => {
                let msg: NsIdMessage = NsIdBuffer::new_checked(&self.inner())
                    .context("invalid nsid message")?
                    .parse()
                    .context("invalid nsid message")?;
                match message_type {
                    RTM_NEWNSID => NewNsId(msg),
                    RTM_DELNSID => DelNsId(msg),
                    RTM_GETNSID => GetNsId(msg),
                    _ => unreachable!(),
                }
            }

            _ => return Err(format!("Unknown message type: {}", message_type).into()),
        };
        Ok(message)
    }
}
