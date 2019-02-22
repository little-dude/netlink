use std::collections::HashMap;

use netlink_sys::constants::AF_PACKET;

use crate::{
    sock_diag::{
        packet::{
            buffer::{Attr, RequestBuffer, ResponseBuffer, Show},
            Fanout, Info, McList, Ring,
        },
        SkMemInfo,
    },
    DecodeError, Emitable, Parseable, ParseableParametrized,
};

const ETH_P_TSN: i32 = 0x22F0; // TSN (IEEE 1722) packet
const ETH_P_ERSPAN2: i32 = 0x22EB; // ERSPAN version 2 (type III)
const ETH_P_ERSPAN: i32 = 0x88BE; // ERSPAN type II
const ETH_P_PREAUTH: i32 = 0x88C7; // 802.11 Preauthentication
const ETH_P_NCSI: i32 = 0x88F8; // NCSI protocol
const ETH_P_IBOE: i32 = 0x8915; // Infiniband over Ethernet
const ETH_P_HSR: i32 = 0x892F; // IEC 62439-3 HSRv1
const ETH_P_NSH: i32 = 0x894F; // Network Service Header
const ETH_P_IFE: i32 = 0xED3E; // ForCES inter-FE LFB type
const ETH_P_LLDP: i32 = 0x88cc; // LLDP

lazy_static! {
    pub static ref PROTO_NAMES: HashMap<i32, &'static str> = {
        let mut m = HashMap::new();

        m.insert(libc::ETH_P_LOOP, "loop"); // Ethernet Loopback packet
        m.insert(libc::ETH_P_PUP, "pup"); // Xerox PUP packet
        m.insert(libc::ETH_P_PUPAT, "pupat"); // Xerox PUP Addr Trans packet
        m.insert(ETH_P_TSN, "tsn"); // TSN (IEEE 1722) packet
        m.insert(ETH_P_ERSPAN2, "erspan2"); // ERSPAN version 2 (type III)
        m.insert(libc::ETH_P_IP, "ipv4"); // Internet Protocol packet
        m.insert(libc::ETH_P_X25, "x25"); // CCITT X.25
        m.insert(libc::ETH_P_ARP, "arp"); // Address Resolution packet
        m.insert(libc::ETH_P_BPQ, "bpq"); // G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ]
        m.insert(libc::ETH_P_IEEEPUP, "ieeepup"); // Xerox IEEE802.3 PUP packet
        m.insert(libc::ETH_P_IEEEPUPAT, "ieeeepupat"); // Xerox IEEE802.3 PUP Addr Trans packet
        m.insert(libc::ETH_P_BATMAN, "batman"); // B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
        m.insert(libc::ETH_P_DEC, "dec"); // DEC Assigned proto
        m.insert(libc::ETH_P_DNA_DL, "dna_dl"); // DEC DNA Dump/Load
        m.insert(libc::ETH_P_DNA_RC, "dna_rc"); // DEC DNA Remote Console
        m.insert(libc::ETH_P_DNA_RT, "dna_rt"); // DEC DNA Routing
        m.insert(libc::ETH_P_LAT, "lat"); // DEC LAT
        m.insert(libc::ETH_P_DIAG, "diag"); // DEC Diagnostics
        m.insert(libc::ETH_P_CUST, "cust"); // DEC Customer use
        m.insert(libc::ETH_P_SCA, "sca"); // DEC Systems Comms Arch
        m.insert(libc::ETH_P_TEB, "teb"); // Trans Ether Bridging
        m.insert(libc::ETH_P_RARP, "rarp"); // Reverse Addr Res packet
        m.insert(libc::ETH_P_ATALK, "atalk"); // Appletalk DDP
        m.insert(libc::ETH_P_AARP, "aarp"); // Appletalk AARP
        m.insert(libc::ETH_P_8021Q, "802.1Q"); // 802.1Q VLAN Extended Header
        m.insert(ETH_P_ERSPAN, "erspan"); // ERSPAN type II
        m.insert(libc::ETH_P_IPX, "ipx"); // IPX over DIX
        m.insert(libc::ETH_P_IPV6, "ipv6"); // IPv6 over bluebook
        m.insert(libc::ETH_P_PAUSE, "pause"); // IEEE Pause frames. See 802.3 31B
        m.insert(libc::ETH_P_SLOW, "slow"); // Slow Protocol. See 802.3ad 43B
        m.insert(libc::ETH_P_WCCP, "wccp"); // Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
        m.insert(libc::ETH_P_MPLS_UC, "mpls_uc"); // MPLS Unicast traffic
        m.insert(libc::ETH_P_MPLS_MC, "mpls_mc"); // MPLS Multicast traffic
        m.insert(libc::ETH_P_ATMMPOA, "atmmpoa"); // MultiProtocol Over ATM
        m.insert(libc::ETH_P_PPP_DISC, "ppp_disc"); // PPPoE discovery messages
        m.insert(libc::ETH_P_PPP_SES, "ppp_ses"); // PPPoE session messages
        m.insert(libc::ETH_P_LINK_CTL, "link_ctl"); // HPNA, wlan link local tunnel
        m.insert(libc::ETH_P_ATMFATE, "atmfate"); // Frame-based ATM Transport over Ethernet
        m.insert(libc::ETH_P_PAE, "pae"); // Port Access Entity (IEEE 802.1X)
        m.insert(libc::ETH_P_AOE, "aoe"); // ATA over Ethernet
        m.insert(libc::ETH_P_8021AD, "802.1ad"); // 802.1ad Service VLAN
        m.insert(libc::ETH_P_802_EX1, "802.1ex1"); // 802.1 Local Experimental 1.
        m.insert(ETH_P_PREAUTH, "preauth"); // 802.11 Preauthentication
        m.insert(libc::ETH_P_TIPC, "tipc"); // TIPC
        m.insert(libc::ETH_P_MACSEC, "macsec"); // 802.1ae MACsec
        m.insert(libc::ETH_P_8021AH, "802.1ah"); // 802.1ah Backbone Service Tag
        m.insert(libc::ETH_P_MVRP, "mvrp"); // 802.1Q MVRP
        m.insert(libc::ETH_P_1588, "ieee_1588"); // IEEE 1588 Timesync
        m.insert(ETH_P_NCSI, "ncsi"); // NCSI protocol
        m.insert(libc::ETH_P_PRP, "prp"); // IEC 62439-3 PRP/HSRv0
        m.insert(libc::ETH_P_FCOE, "fcoe"); // Fibre Channel over Ethernet
        m.insert(ETH_P_IBOE, "iboe"); // Infiniband over Ethernet
        m.insert(libc::ETH_P_TDLS, "tdls"); // TDLS
        m.insert(libc::ETH_P_FIP, "fip"); // FCoE Initialization Protocol
        m.insert(libc::ETH_P_80221, "802.21"); // IEEE 802.21 Media Independent Handover Protocol
        m.insert(ETH_P_HSR, "hsr"); // IEC 62439-3 HSRv1
        m.insert(ETH_P_NSH, "nsh"); // Network Service Header
        m.insert(libc::ETH_P_LOOPBACK, "loopback"); // Ethernet loopback packet, per IEEE 802.3
        m.insert(libc::ETH_P_QINQ1, "qinq1"); // deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
        m.insert(libc::ETH_P_QINQ2, "qinq2"); // deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
        m.insert(libc::ETH_P_QINQ3, "qinq3"); // deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
        m.insert(libc::ETH_P_EDSA, "edsa"); // Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
        m.insert(ETH_P_IFE, "ife"); // ForCES inter-FE LFB type
        m.insert(libc::ETH_P_AF_IUCV, "af_iucv"); // IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]
        m.insert(ETH_P_LLDP, "LLDP");
        m
    };
}

/// The request for `AF_PACKET` sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Request {
    /// This is an inode number when querying for an individual socket.
    ///
    /// Ignored when querying for a list of sockets.
    pub inode: u32,
    /// This is a set of flags defining what kind of information to report.
    ///
    /// Each requested kind of information is reported back as a netlink attribute
    pub show: Show,
    /// This is an opaque identifiers that could be used to specify an individual socket.
    pub cookie: Option<u64>,
}

impl Request {
    pub fn new() -> Self {
        Request::default()
    }

    pub fn with_inode(mut self, inode: u32) -> Self {
        self.inode = inode;
        self
    }

    pub fn with_show(mut self, show: Show) -> Self {
        self.show.insert(show);
        self
    }

    pub fn with_cookie(mut self, cookie: u64) -> Self {
        self.cookie = Some(cookie);
        self
    }
}

impl Default for Request {
    fn default() -> Self {
        Request {
            inode: 0,
            show: Show::INFO,
            cookie: None,
        }
    }
}

impl Emitable for Request {
    fn buffer_len(&self) -> usize {
        RequestBuffer::<()>::len()
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut req = RequestBuffer::new(buf);

        req.set_family(AF_PACKET as u8);
        req.set_protocol(0);
        req.set_inode(self.inode);
        req.set_show(self.show);
        req.set_cookie(self.cookie)
    }
}

/// The response to a query for `AF_PACKET` sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    /// The address family
    ///
    /// It should be set to `AF_PACKET`.
    pub family: u8,
    /// This is set to one of `packet_type`.
    pub ty: u8,
    /// This is the ethernet protocol ID.
    pub proto: u16,
    /// This is the socket inode number.
    pub inode: u32,
    /// This is an opaque identifiers that could be used in subsequent queries.
    pub cookie: Option<u64>,
    /// socket attributes
    pub attrs: Vec<Attr>,
}

impl Response {
    pub fn info(&self) -> Option<&Info> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Info(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn mclist(&self) -> Option<&[McList]> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::McList(ref value) = attr {
                    Some(value.as_slice())
                } else {
                    None
                }
            })
            .next()
    }

    pub fn rx_ring(&self) -> Option<&Ring> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::RxRing(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn tx_ring(&self) -> Option<&Ring> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::TxRing(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn fanout(&self) -> Option<&Fanout> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Fanout(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn uid(&self) -> Option<u32> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Uid(value) = attr {
                    Some(*value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn meminfo(&self) -> Option<&SkMemInfo> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::MemInfo(ref value) = attr {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn filter(&self) -> Option<&[u8]> {
        self.attrs
            .iter()
            .filter_map(|attr| {
                if let Attr::Filter(ref value) = attr {
                    Some(value.as_ref())
                } else {
                    None
                }
            })
            .next()
    }
}

impl<T: AsRef<[u8]>> Parseable<Response> for ResponseBuffer<T> {
    fn parse(&self) -> Result<Response, DecodeError> {
        let attrs = self
            .attrs()
            .map(|(ty, payload)| payload.parse_with_param(ty))
            .collect::<Result<Vec<_>, DecodeError>>()?;

        Ok(Response {
            family: self.family(),
            ty: self.ty(),
            proto: self.num(),
            inode: self.inode(),
            cookie: self.cookie(),
            attrs,
        })
    }
}
