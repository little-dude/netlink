#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;

use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::fmt;
use std::fs;
use std::mem;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::ptr::{self, NonNull};
use std::str::FromStr;

use failure::{bail, format_err, Error};
use futures::{future, Future, IntoFuture, Stream};
use libc::{
    IPPROTO_DCCP, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET,
    SOCK_STREAM,
};
use structopt::StructOpt;
use tokio_core::reactor::Core;
use try_from::TryFrom;

use sock_diag::{
    constants::*,
    packet::sock_diag::{
        netlink, packet, Expr, Extensions, InetDiagResponse, NetlinkDiagResponse, NetlinkShow,
        PacketDiagResponse, PacketShow, SctpState, SockState::*, SockStates, UnixDiagResponse,
        UnixShow,
    },
    Handle,
};

#[derive(Debug, StructOpt)]
#[structopt(name = "netstat", about = "An example of print network connections.")]
/// ss [ OPTIONS ] [ FILTER ]
struct Opt {
    /// don't resolve service names
    #[structopt(short = "n", long = "numeric")]
    no_resolve_services: bool,

    /// resolve host names
    #[structopt(short = "r", long = "resolve")]
    resolve_hosts: bool,

    /// display all sockets
    #[structopt(short = "a", long = "all")]
    all: bool,

    /// display listening sockets
    #[structopt(short = "l", long = "listening")]
    listening: bool,

    /// show timer information
    #[structopt(short = "o", long = "options")]
    show_options: bool,

    /// show detailed socket information
    #[structopt(short = "e", long = "extended")]
    show_details: bool,

    /// show socket memory usage
    #[structopt(short = "m", long = "memory")]
    show_mem: bool,

    /// show process using socket
    #[structopt(short = "p", long = "processes")]
    show_users: bool,

    /// show internal TCP information
    #[structopt(short = "i", long = "info")]
    show_tcpinfo: bool,

    /// show socket usage summary
    #[structopt(short = "s", long = "summary")]
    do_summary: bool,

    /// show bpf filter socket information
    #[structopt(short = "b", long = "bpf")]
    bpf: bool,

    /// continually display sockets as they are destroyed
    #[structopt(short = "E", long = "events")]
    follow_events: bool,

    /// display only IP version 4 sockets
    #[structopt(short = "4", long = "ipv4")]
    ipv4: bool,

    /// display only IP version 6 sockets
    #[structopt(short = "6", long = "ipv6")]
    ipv6: bool,

    /// display PACKET sockets
    #[structopt(short = "0", long = "packet")]
    packet: bool,

    /// display only TCP sockets
    #[structopt(short = "t", long = "tcp")]
    tcp: bool,

    /// display only SCTP sockets
    #[structopt(short = "S", long = "sctp")]
    sctp: bool,

    /// display only UDP sockets
    #[structopt(short = "u", long = "udp")]
    udp: bool,

    /// display only DCCP sockets
    #[structopt(short = "d", long = "dccp")]
    dccp: bool,

    /// display only Unix domain sockets
    #[structopt(short = "x", long = "unix")]
    unix: bool,

    /// display sockets of type FAMILY {inet|inet6|link|unix|netlink|help}
    #[structopt(name = "FAMILY", short = "f", long = "family")]
    family: Option<Family>,

    /// forcibly close sockets, display what was closed
    #[structopt(short = "K", long = "kill")]
    kill: bool,

    /// Suppress header line
    #[structopt(short = "H", long = "no-header")]
    no_header: bool,

    /// QUERY := {all|inet|tcp|udp|raw|unix|unix_dgram|unix_stream|unix_seqpacket|packet|netlink}[,QUERY]
    #[structopt(short = "A", long = "query")]
    query: Vec<Proto>,

    /// read filter information from FILE
    #[structopt(name = "FILTER_FILE", short = "F", long = "filter")]
    read_filter: Option<String>,

    #[doc = "FILTER := [ state STATE-FILTER ] [ EXPRESSION ]
    STATE-FILTER := {all|connected|synchronized|bucket|big|TCP-STATES}
      TCP-STATES := {established|syn-sent|syn-recv|fin-wait-{1,2}|time-wait|closed|close-wait|last-ack|listen|closing}
       connected := {established|syn-sent|syn-recv|fin-wait-{1,2}|time-wait|close-wait|last-ack|closing}
    synchronized := {established|syn-recv|fin-wait-{1,2}|time-wait|close-wait|last-ack|closing}
          bucket := {syn-recv|time-wait}
             big := {established|syn-sent|fin-wait-{1,2}|closed|close-wait|last-ack|listen|closing}
    "]
    #[structopt(name = "FILTER")]
    filter: Vec<String>,
}

impl Opt {
    fn resolve_services(&self) -> bool {
        !self.no_resolve_services
    }
}

bitflags! {
    struct Family: u32 {
        const UNIX      = 1 << AF_UNIX;
        const INET      = 1 << AF_INET;
        const INET6     = 1 << AF_INET6;
        const NETLINK   = 1 << AF_NETLINK;
        const PACKET    = 1 << AF_PACKET;
    }
}

impl From<u8> for Family {
    fn from(af: u8) -> Self {
        Self::from_bits_truncate(1 << af)
    }
}

impl FromStr for Family {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let family = match s {
            "inet" => Family::INET,
            "inet6" => Family::INET6,
            "link" => Family::PACKET,
            "unix" => Family::UNIX,
            "netlink" => Family::NETLINK,
            "help" => bail!("show help"),
            _ => bail!("{} is invalid family", s),
        };

        Ok(family)
    }
}

#[allow(non_camel_case_types)]
enum Protocol {
    TCP,
    DCCP,
    UDP,
    UNIX_DG,
    UNIX_ST,
    UNIX_SQ,
    PACKET_DG,
    PACKET_R,
    NETLINK,
    SCTP,
}

bitflags! {
    struct Proto: u32 {
        const TCP       = 1 << Protocol::TCP as usize;
        const DCCP      = 1 << Protocol::DCCP as usize;
        const UDP       = 1 << Protocol::UDP as usize;
        const UNIX_DG   = 1 << Protocol::UNIX_DG as usize;
        const UNIX_ST   = 1 << Protocol::UNIX_ST as usize;
        const UNIX_SQ   = 1 << Protocol::UNIX_SQ as usize;
        const PACKET_DG = 1 << Protocol::PACKET_DG as usize;
        const PACKET_R  = 1 << Protocol::PACKET_R as usize;
        const NETLINK   = 1 << Protocol::NETLINK as usize;
        const SCTP      = 1 << Protocol::SCTP as usize;
        const INET      = Self::TCP.bits | Self::UDP.bits | Self::DCCP.bits | Self::SCTP.bits;
        const UNIX      = Self::UNIX_DG.bits | Self::UNIX_SQ.bits | Self::UNIX_ST.bits;
        const PACKET    = Self::PACKET_DG.bits | Self::PACKET_R.bits;
    }
}

impl Proto {
    pub fn len(&self) -> usize {
        self.bits.count_ones() as usize
    }
}

impl FromStr for Proto {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ty = match s {
            "all" => Proto::all(),
            "inet" => Proto::INET,
            "udp" => Proto::UDP,
            "tcp" => Proto::TCP,
            "dccp" => Proto::DCCP,
            "sctp" => Proto::SCTP,
            "unix" => Proto::UNIX,
            "unix_stream" | "u_str" => Proto::UNIX_ST,
            "unix_dgram" | "u_dgr" => Proto::UNIX_DG,
            "unix_seqpacket" | "u_seq" => Proto::UNIX_SQ,
            "packet" => Proto::PACKET,
            "packet_raw" | "p_raw" => Proto::PACKET_R,
            "packet_dgram" | "p_dgr" => Proto::PACKET_DG,
            "netlink" => Proto::NETLINK,
            _ => bail!("{} is illegal socket table id", s),
        };

        Ok(ty)
    }
}

lazy_static! {
    static ref DEFAULT_PROTOS: HashMap<Proto, (SockStates, Family)> = {
        let mut m = HashMap::new();

        m.insert(
            Proto::TCP,
            (SockStates::conn(), Family::INET | Family::INET6),
        );
        m.insert(
            Proto::DCCP,
            (SockStates::conn(), Family::INET | Family::INET6),
        );
        m.insert(
            Proto::SCTP,
            (SockStates::conn(), Family::INET | Family::INET6),
        );
        m.insert(
            Proto::UDP,
            (SockStates::ESTABLISHED, Family::INET | Family::INET6),
        );
        m.insert(Proto::UNIX_DG, (SockStates::CLOSE, Family::UNIX));
        m.insert(Proto::UNIX_ST, (SockStates::conn(), Family::UNIX));
        m.insert(Proto::UNIX_SQ, (SockStates::conn(), Family::UNIX));
        m.insert(Proto::PACKET_DG, (SockStates::CLOSE, Family::PACKET));
        m.insert(Proto::PACKET_R, (SockStates::CLOSE, Family::PACKET));
        m.insert(Proto::NETLINK, (SockStates::CLOSE, Family::NETLINK));
        m
    };
    static ref DEFAULT_FAMILIES: HashMap<Family, (SockStates, Proto)> = {
        let mut m = HashMap::new();

        m.insert(Family::INET, (SockStates::conn(), Proto::INET));
        m.insert(Family::INET6, (SockStates::conn(), Proto::INET));
        m.insert(Family::UNIX, (SockStates::conn(), Proto::UNIX));
        m.insert(Family::PACKET, (SockStates::CLOSE, Proto::PACKET));
        m.insert(Family::NETLINK, (SockStates::CLOSE, Proto::NETLINK));
        m
    };
}

impl Opt {
    fn families(&self) -> Family {
        let mut families = if self.all {
            Family::all()
        } else {
            Family::empty()
        };

        if self.unix {
            families |= Family::UNIX;
        }
        if self.ipv4 {
            families |= Family::INET;
        }
        if self.ipv6 {
            families |= Family::INET6;
        }
        if self.packet {
            families |= Family::PACKET;
        }
        if let Some(v) = self.family {
            families |= v;
        }

        families
    }

    fn protos(&self) -> Proto {
        let mut protos = if self.all {
            Proto::all()
        } else {
            Proto::empty()
        };

        if self.dccp {
            protos |= Proto::DCCP;
        }
        if self.tcp {
            protos |= Proto::TCP;
        }
        if self.sctp {
            protos |= Proto::SCTP;
        }
        if self.udp {
            protos |= Proto::UDP;
        }

        protos
    }

    fn states(&self) -> SockStates {
        if self.all {
            SockStates::all()
        } else if self.listening {
            SockStates::LISTEN | SockStates::CLOSE
        } else if !self.query.is_empty() {
            SockStates::conn()
        } else {
            match self.filter.first().map(|s| s.as_str()) {
                Some("state") => SockStates::empty(),
                Some("exclude") | Some("excl") => SockStates::all(),
                _ => SockStates::empty(),
            }
        }
    }

    fn build(mut self) -> Result<SockDiag, Error> {
        let mut families = self.families();
        let mut protos = self.protos();
        let mut states = self.states();

        if families.is_empty() {
            for (p, (s, f)) in DEFAULT_PROTOS.iter() {
                if protos.contains(*p) {
                    debug!(
                        "add family {:?} with states {:?} base on protocol {:?}",
                        f, s, p
                    );

                    families.insert(*f);
                    states.insert(*s);
                }
            }
        }
        if protos.is_empty() {
            for (f, (s, p)) in DEFAULT_FAMILIES.iter() {
                if families.contains(*f) {
                    debug!(
                        "add protocol {:?} with states {:?} base on family {:?}",
                        p, s, f
                    );

                    protos.insert(*p);
                    states.insert(*s);
                }
            }
        }
        if protos.is_empty() && families.is_empty() && self.query.is_empty() {
            protos = Proto::all();

            for (p, (s, f)) in DEFAULT_PROTOS.iter() {
                if protos.contains(*p) {
                    families.insert(*f);
                    states.insert(*s);
                }
            }
        }

        while let Some(keyword) = self.filter.first() {
            match keyword.as_str() {
                "state" if self.filter.len() > 1 => {
                    states.insert(self.filter.drain(..2).last().unwrap().as_str().parse()?)
                }
                "exclude" | "excl" if self.filter.len() > 1 => {
                    states.remove(self.filter.drain(..2).last().unwrap().as_str().parse()?)
                }
                _ => break,
            }
        }

        let expr = if !self.filter.is_empty() {
            let filter = self.filter.join(" ");
            let expr = filter.parse()?;

            debug!("filter `{}` compiled to {:?}", filter, expr);

            Some(expr)
        } else {
            None
        };

        debug!(
            "filter protos: {:?}, family: {:?}, states: {:?}",
            protos, families, states
        );

        if protos.is_empty() {
            bail!("no socket tables to show with such filter.")
        }
        if families.is_empty() {
            bail!("no families to show with such filter.")
        }
        if states.is_empty() {
            bail!("no socket states to show with such filter.")
        }

        Ok(SockDiag::new(self, families, protos, states, expr))
    }
}

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let opts = Opt::from_args();

    debug!("parsed options: {:?}", opts);

    let sock_diag = opts.build()?;

    if !sock_diag.no_header {
        println!("{}", SockDiagHeader::new(&sock_diag));
    }

    if sock_diag.follow_events {
        sock_diag.handle_follow_request()
    } else {
        if sock_diag.protos.contains(Proto::NETLINK) && sock_diag.families.contains(Family::NETLINK)
        {
            sock_diag.netlink_show_netlink()?;
        }
        if sock_diag.protos.contains(Proto::PACKET) && sock_diag.families.contains(Family::PACKET) {
            sock_diag.packet_show_netlink()?;
        }
        if sock_diag.protos.contains(Proto::UNIX) && sock_diag.families.contains(Family::UNIX) {
            sock_diag.unix_show_netlink()?;
        }
        if sock_diag.families.contains(Family::INET) || sock_diag.families.contains(Family::INET6) {
            if sock_diag.protos.contains(Proto::UDP) {
                sock_diag.inet_show_netlink(IPPROTO_UDP as u8)?;
            }
            if sock_diag.protos.contains(Proto::TCP) {
                sock_diag.inet_show_netlink(IPPROTO_TCP as u8)?;
            }
            if sock_diag.protos.contains(Proto::DCCP) {
                sock_diag.inet_show_netlink(IPPROTO_DCCP as u8)?;
            }
            if sock_diag.protos.contains(Proto::SCTP) {
                sock_diag.inet_show_netlink(IPPROTO_SCTP as u8)?;
            }
        }

        Ok(())
    }
}

struct SockDiag {
    opts: Opt,
    families: Family,
    protos: Proto,
    states: SockStates,
    expr: Option<Expr>,
}

impl Deref for SockDiag {
    type Target = Opt;

    fn deref(&self) -> &Self::Target {
        &self.opts
    }
}

impl SockDiag {
    pub fn new(
        opts: Opt,
        families: Family,
        protos: Proto,
        states: SockStates,
        expr: Option<Expr>,
    ) -> Self {
        SockDiag {
            opts,
            families,
            protos,
            states,
            expr,
        }
    }

    fn handle_request<F, R>(&self, callback: F) -> Result<(), Error>
    where
        F: FnOnce(Handle) -> R,
        R: IntoFuture<Error = Error>,
    {
        let (conn, handle) = sock_diag::new_connection()?;

        let mut core = Core::new()?;
        core.handle().spawn(conn.map_err(|_| ()));
        core.run(future::lazy(|| callback(handle)))
            .map_err(|err| format_err!("fail to handle request, {}", err))?;

        Ok(())
    }

    fn netlink_show_netlink(&self) -> Result<(), Error> {
        self.handle_request(|handle| {
            handle
                .netlink()
                .list()
                .with_show(NetlinkShow::GROUPS | NetlinkShow::MEMINFO)
                .execute()
                .for_each(|res| {
                    println!("{}", NetlinkSockFmt::new(self, &res));

                    Ok(())
                })
        })
    }

    fn packet_show_netlink(&self) -> Result<(), Error> {
        self.handle_request(|handle| {
            handle
                .packet()
                .list()
                .with_show(
                    PacketShow::INFO
                        | PacketShow::MEMINFO
                        | PacketShow::FILTER
                        | PacketShow::RING_CFG
                        | PacketShow::FANOUT,
                )
                .execute()
                .for_each(|res| {
                    println!("{}", PacketSockFmt::new(self, &res));

                    Ok(())
                })
        })
    }

    fn unix_show_netlink(&self) -> Result<(), Error> {
        self.handle_request(|handle| {
            handle
                .unix()
                .list()
                .with_states(self.states.into())
                .with_show({
                    let mut show = UnixShow::NAME | UnixShow::PEER | UnixShow::RQLEN;

                    if self.show_mem {
                        show |= UnixShow::MEMINFO;
                    }

                    show
                })
                .execute()
                .for_each(|res| {
                    if (res.ty == SOCK_STREAM as u8 && self.protos.contains(Proto::UNIX_ST))
                        | (res.ty == SOCK_DGRAM as u8 && self.protos.contains(Proto::UNIX_DG))
                        | (res.ty == SOCK_SEQPACKET as u8 && self.protos.contains(Proto::UNIX_SQ))
                    {
                        println!("{}", UnixSockFmt::new(self, &res));
                    }

                    Ok(())
                })
        })
    }

    fn inet_show_netlink(&self, proto: u8) -> Result<(), Error> {
        let send_request = |handle: Handle, family| {
            handle
                .inet()
                .list(family, proto)
                .with_states(self.states.into())
                .with_extensions({
                    let mut ext = Extensions::empty();

                    if self.show_mem {
                        ext |= Extensions::MEMINFO | Extensions::SKMEMINFO;
                    }
                    if self.show_tcpinfo {
                        ext |= Extensions::INFO | Extensions::VEGASINFO | Extensions::CONF;
                    }

                    ext
                })
                .with_expr(self.expr.clone())
                .execute()
                .for_each(|res| {
                    if self.families.contains(res.family.into()) {
                        println!("{}", InetSockFmt::new(self, &res, proto));
                    }

                    Ok(())
                })
        };

        if self.families.contains(Family::INET) {
            self.handle_request(|handle| send_request(handle, AF_INET as u8))?;
        }
        if self.families.contains(Family::INET6) {
            self.handle_request(|handle| send_request(handle, AF_INET6 as u8))?;
        }

        Ok(())
    }

    fn handle_follow_request(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Layout {
    netid_width: Option<usize>,
    state_width: Option<usize>,
    addr_width: usize,
    serv_width: usize,
}

impl Layout {
    fn new(sock_diag: &SockDiag) -> Self {
        let netid_width = if sock_diag.protos.len() > 1 {
            Some(5)
        } else {
            None
        };
        let state_width = if sock_diag.states.len() > 1 {
            Some(10)
        } else {
            None
        };
        let screen_width = term_size::dimensions().map_or(80, |(w, _)| w);
        let mut serv_width = if sock_diag.resolve_services() { 7 } else { 5 };
        let mut addr_width = screen_width
            .checked_sub(netid_width.map(|w| w + 1).unwrap_or_default())
            .and_then(|w| w.checked_sub(state_width.map(|w| w + 1).unwrap_or_default()))
            .and_then(|w| w.checked_sub(14))
            .and_then(|w| w.checked_div(2))
            .and_then(|w| w.checked_sub(1))
            .unwrap_or_default()
            .max(15 + serv_width + 1)
            - (serv_width + 1);

        addr_width -= 13;
        serv_width += 13;

        Layout {
            netid_width,
            state_width,
            addr_width,
            serv_width,
        }
    }
}

struct SockDiagFmt<'a> {
    sock_diag: &'a SockDiag,
    layout: Layout,
}

impl<'a> Deref for SockDiagFmt<'a> {
    type Target = SockDiag;

    fn deref(&self) -> &Self::Target {
        self.sock_diag
    }
}

impl<'a> SockDiagFmt<'a> {
    fn new(sock_diag: &'a SockDiag) -> Self {
        SockDiagFmt {
            sock_diag,
            layout: Layout::new(sock_diag),
        }
    }
}

struct SockDiagHeader<'a>(SockDiagFmt<'a>);

impl<'a> Deref for SockDiagHeader<'a> {
    type Target = SockDiagFmt<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> SockDiagHeader<'a> {
    fn new(sock_diag: &'a SockDiag) -> Self {
        SockDiagHeader(SockDiagFmt::new(sock_diag))
    }
}

impl<'a> fmt::Display for SockDiagHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(width) = self.layout.netid_width {
            write!(f, "{:<width$} ", "Netid", width = width)?;
        }
        if let Some(width) = self.layout.state_width {
            write!(f, "{:<width$} ", "State", width = width)?;
        }

        write!(
            f,
            "{:<6} {:<6} {:>addr_width$}:{:<serv_width$}{:>addr_width$}:{:<serv_width$}",
            "Recv-Q",
            "Send-Q",
            "Local Address",
            "Port",
            "Peer Address",
            "Port",
            addr_width = self.layout.addr_width,
            serv_width = self.layout.serv_width
        )
    }
}

struct NetlinkSockFmt<'a> {
    sock_diag: SockDiagFmt<'a>,
    res: &'a NetlinkDiagResponse,
}

impl<'a> Deref for NetlinkSockFmt<'a> {
    type Target = SockDiagFmt<'a>;

    fn deref(&self) -> &Self::Target {
        &self.sock_diag
    }
}

impl<'a> NetlinkSockFmt<'a> {
    fn new(sock_diag: &'a SockDiag, res: &'a NetlinkDiagResponse) -> Self {
        NetlinkSockFmt {
            sock_diag: SockDiagFmt::new(sock_diag),
            res,
        }
    }
}

impl<'a> fmt::Display for NetlinkSockFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(width) = self.layout.netid_width {
            write!(f, "{:<width$} ", "nl", width = width)?;
        }
        if let Some(width) = self.layout.state_width {
            write!(
                f,
                "{:<width$} ",
                SockStateName(SS_CLOSE as u8),
                width = width
            )?;
        }

        let (rq, sq) = self
            .res
            .meminfo()
            .map(|info| (info.rmem_alloc, info.wmem_alloc))
            .unwrap_or_default();

        write!(f, "{:<6} {:<6} ", rq, sq)?;

        let proto = self.res.proto as isize;
        let proto_name: Cow<str> = if self.resolve_services() {
            netlink::PROTO_NAMES.get(&proto).map(|s| (*s).into()).into()
        } else {
            None
        }
        .unwrap_or_else(|| format!("{}", self.res.proto).into());

        let pid = self.res.portid;
        let proc_name: Cow<str> = if pid == -1 {
            "*".into()
        } else if pid == 0 {
            "kernel".into()
        } else if pid > 0 {
            let mut path = PathBuf::from(env::var_os("PROC_ROOT").unwrap_or("/proc".into()));

            path.push(format!("{}", pid));
            path.push("stat");

            format!(
                "{}/{}",
                fs::read_to_string(&path)
                    .map_err(|err| {
                        warn!("fail to read {:?}, {}", path, err);

                        fmt::Error
                    })?
                    .split(' ')
                    .skip(1)
                    .next()
                    .unwrap()
                    .trim_start_matches('(')
                    .trim_end_matches(')'),
                pid
            )
            .into()
        } else {
            format!("{}", pid).into()
        };

        let addr_width = self.layout.addr_width;
        let serv_width = self.layout.serv_width;

        write!(
            f,
            "{:>addr_width$}:{:<serv_width$}",
            proto_name,
            proc_name,
            addr_width = addr_width,
            serv_width = serv_width
        )?;

        if self.res.state == NETLINK_CONNECTED as u8 {
            write!(
                f,
                "{:>addr_width$}:{:<serv_width$}",
                self.res.dst_group,
                self.res.dst_portid,
                addr_width = addr_width,
                serv_width = serv_width
            )?;
        } else {
            write!(
                f,
                "{:>addr_width$}*{:<serv_width$}",
                "",
                "",
                addr_width = addr_width,
                serv_width = serv_width
            )?;
        }

        if self.show_details {
            // TODO
        }

        Ok(())
    }
}

struct PacketSockFmt<'a> {
    sock_diag: SockDiagFmt<'a>,
    res: &'a PacketDiagResponse,
}

impl<'a> Deref for PacketSockFmt<'a> {
    type Target = SockDiagFmt<'a>;

    fn deref(&self) -> &Self::Target {
        &self.sock_diag
    }
}

impl<'a> PacketSockFmt<'a> {
    fn new(sock_diag: &'a SockDiag, res: &'a PacketDiagResponse) -> Self {
        PacketSockFmt {
            sock_diag: SockDiagFmt::new(sock_diag),
            res,
        }
    }
}

impl<'a> fmt::Display for PacketSockFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        PacketStateFmt(self).fmt(f)?;

        let (rq, sq) = self
            .res
            .meminfo()
            .map(|info| (info.rmem_alloc, info.wmem_alloc))
            .unwrap_or_default();

        write!(f, "{:<6} {:<6} ", rq, sq)?;

        let proto: Cow<str> = if self.res.proto as i32 == SOCK_RAW {
            "*".into()
        } else {
            let proto = self.res.proto as i32;

            packet::PROTO_NAMES
                .get(&proto)
                .map(|s| (*s).into())
                .unwrap_or_else(|| format!("[{}]", self.res.proto).into())
        };

        write!(f, "{:>width$}", proto, width = self.layout.addr_width)?;

        let ifname: Cow<str> = self
            .res
            .info()
            .map(|info| info.pdi_index)
            .and_then(|ifindex| {
                pnet_datalink::interfaces()
                    .into_iter()
                    .find(|intf| intf.index == ifindex)
                    .map(|intf| intf.name.into())
            })
            .unwrap_or("*".into());

        write!(f, ":{:<width$}", ifname, width = self.layout.serv_width)?;

        write!(
            f,
            "{:>addr_width$}*{:<serv_width$}",
            "",
            "",
            addr_width = self.layout.addr_width,
            serv_width = self.layout.serv_width
        )?;

        if self.show_users {
            // TODO
        }

        if self.show_details {
            // TODO
        }

        Ok(())
    }
}

struct PacketStateFmt<'a>(&'a PacketSockFmt<'a>);

impl<'a> Deref for PacketStateFmt<'a> {
    type Target = PacketSockFmt<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> fmt::Display for PacketStateFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", PacketSockStateFmt(self),)
    }
}

struct PacketSockStateFmt<'a>(&'a PacketStateFmt<'a>);

impl<'a> Deref for PacketSockStateFmt<'a> {
    type Target = PacketStateFmt<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> fmt::Display for PacketSockStateFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(width) = self.layout.netid_width {
            write!(
                f,
                "{:<width$} ",
                if self.res.ty == SOCK_RAW as u8 {
                    "p_raw"
                } else {
                    "p_dgr"
                },
                width = width
            )?;
        }
        if let Some(width) = self.layout.state_width {
            write!(
                f,
                "{:<width$} ",
                SockStateName(SS_CLOSE as u8),
                width = width
            )?;
        }

        Ok(())
    }
}

struct UnixSockFmt<'a> {
    sock_diag: SockDiagFmt<'a>,
    res: &'a UnixDiagResponse,
}

impl<'a> Deref for UnixSockFmt<'a> {
    type Target = SockDiagFmt<'a>;

    fn deref(&self) -> &Self::Target {
        &self.sock_diag
    }
}

impl<'a> UnixSockFmt<'a> {
    fn new(sock_diag: &'a SockDiag, res: &'a UnixDiagResponse) -> Self {
        UnixSockFmt {
            sock_diag: SockDiagFmt::new(sock_diag),
            res,
        }
    }
}

impl<'a> fmt::Display for UnixSockFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        UnixStateFmt(self).fmt(f)?;

        if self.show_mem {
            // TODO
        }

        if self.show_details {
            // TODO
        }

        Ok(())
    }
}

struct UnixStateFmt<'a>(&'a UnixSockFmt<'a>);

impl<'a> Deref for UnixStateFmt<'a> {
    type Target = UnixSockFmt<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> fmt::Display for UnixStateFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            UnixSockStateFmt(self),
            UnixAddrFmt::new(&self.layout, self.res.name(), self.res.inode),
            UnixAddrFmt::new(&self.layout, None, self.res.peer().unwrap_or_default()),
        )
    }
}

struct UnixSockStateFmt<'a>(&'a UnixStateFmt<'a>);

impl<'a> Deref for UnixSockStateFmt<'a> {
    type Target = UnixStateFmt<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> fmt::Display for UnixSockStateFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(width) = self.layout.netid_width {
            let tyname = match self.res.ty as i32 {
                SOCK_STREAM => "u_str",
                SOCK_SEQPACKET => "u_seq",
                SOCK_DGRAM => "u_dgr",
                _ => "???",
            };

            write!(f, "{:<width$} ", tyname, width = width)?;
        }

        if let Some(width) = self.layout.state_width {
            write!(
                f,
                "{:<width$} ",
                SockStateName(self.res.state as u8),
                width = width
            )?;
        }

        write!(f, "{:<6} {:<6} ", 0, 0)
    }
}

struct UnixAddrFmt<'a> {
    layout: &'a Layout,
    name: Option<&'a str>,
    inode: u32,
}

impl<'a> UnixAddrFmt<'a> {
    fn new(layout: &'a Layout, name: Option<&'a str>, inode: u32) -> Self {
        UnixAddrFmt {
            layout,
            name,
            inode,
        }
    }
}

impl<'a> fmt::Display for UnixAddrFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(name) = self.name {
            write!(f, "{:>width$}", name, width = self.layout.addr_width)?;
        } else {
            write!(f, "{:>width$}", "*", width = self.layout.addr_width)?;
        }

        write!(f, " {:<width$}", self.inode, width = self.layout.serv_width)
    }
}

struct InetSockFmt<'a> {
    sock_diag: SockDiagFmt<'a>,
    res: &'a InetDiagResponse,
    proto: u8,
}

impl<'a> Deref for InetSockFmt<'a> {
    type Target = SockDiagFmt<'a>;

    fn deref(&self) -> &Self::Target {
        &self.sock_diag
    }
}

impl<'a> InetSockFmt<'a> {
    fn new(sock_diag: &'a SockDiag, res: &'a InetDiagResponse, proto: u8) -> Self {
        InetSockFmt {
            sock_diag: SockDiagFmt::new(sock_diag),
            res,
            proto,
        }
    }
}

impl<'a> fmt::Display for InetSockFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        InetStateFmt(self).fmt(f)?;

        if self.show_options {
            // TODO
        }

        if self.show_details {
            // TODO
        }

        if self.show_mem || self.show_tcpinfo {
            // TODO
        }

        Ok(())
    }
}

struct InetStateFmt<'a>(&'a InetSockFmt<'a>);

impl<'a> Deref for InetStateFmt<'a> {
    type Target = InetSockFmt<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> fmt::Display for InetStateFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            InetSockStateFmt(self),
            InetAddrFmt::new(
                &self.layout,
                self.resolve_services(),
                self.res.src,
                Some(self.res.interface),
            ),
            InetAddrFmt::new(&self.layout, self.resolve_services(), self.res.dst, None),
        )?;

        if self.show_users {
            // TODO
        }

        Ok(())
    }
}

struct InetSockStateFmt<'a>(&'a InetStateFmt<'a>);

impl<'a> Deref for InetSockStateFmt<'a> {
    type Target = InetStateFmt<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> InetSockStateFmt<'a> {
    // SCTP assocs share the same inode number with their parent endpoint.
    // So if we have seen the inode number before,
    // it must be an assoc instead of the next endpoint.
    fn is_sctp_assoc(&self) -> bool {
        self.proto == IPPROTO_SCTP as u8
    }
}

impl<'a> fmt::Display for InetSockStateFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(width) = self.layout.netid_width {
            if self.is_sctp_assoc() {
                write!(f, "{:<width$} ", "", width = width)?;
            } else {
                write!(f, "{:<width$} ", ProtoName(self.proto), width = width)?;
            }
        }

        if let Some(width) = self.layout.state_width {
            if self.is_sctp_assoc() {
                write!(
                    f,
                    "- {:<width$} ",
                    SctpStateName(self.res.state),
                    width = width - 3
                )?;
            } else {
                write!(
                    f,
                    "{:<width$} ",
                    SockStateName(self.res.state),
                    width = width
                )?;
            }
        }

        write!(f, "{:<6} {:<6} ", self.res.rqueue, self.res.wqueue)
    }
}

struct InetAddrFmt<'a> {
    layout: &'a Layout,
    resolve_services: bool,
    addr: Option<SocketAddr>,
    interface: Option<u32>,
}

impl<'a> InetAddrFmt<'a> {
    fn new(
        layout: &'a Layout,
        resolve_services: bool,
        addr: Option<SocketAddr>,
        interface: Option<u32>,
    ) -> Self {
        InetAddrFmt {
            layout,
            resolve_services,
            addr,
            interface,
        }
    }
}

impl<'a> fmt::Display for InetAddrFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ifname = self.interface.and_then(|ifindex| {
            pnet_datalink::interfaces()
                .into_iter()
                .find(|intf| intf.index == ifindex)
                .map(|intf| intf.name)
        });

        let addr_width = self
            .layout
            .addr_width
            .checked_sub(ifname.as_ref().map(|s| s.len() + 1).unwrap_or_default())
            .unwrap_or_default();

        if let Some(addr) = self.addr {
            write!(f, "{:>width$}", addr.ip().to_string(), width = addr_width)?;
        } else {
            write!(f, "{:>width$}", "*", width = addr_width)?;
        }

        if let Some(ifname) = ifname {
            write!(f, "%{}", ifname)?;
        }

        write!(f, ":")?;

        if let Some(addr) = self.addr {
            if self.resolve_services {
                let servname = unsafe {
                    NonNull::new(getservbyport(addr.port().to_be() as i32, ptr::null()))
                        .and_then(|servent| CStr::from_ptr(servent.as_ref().s_name).to_str().ok())
                };

                if let Some(servname) = servname {
                    write!(f, "{:<width$}", servname, width = self.layout.serv_width)
                } else {
                    write!(f, "{:<width$}", addr.port(), width = self.layout.serv_width)
                }
            } else {
                write!(f, "{:<width$}", addr.port(), width = self.layout.serv_width)
            }
        } else {
            write!(f, "{:<width$}", "*", width = self.layout.serv_width)
        }
    }
}

extern "C" {
    fn getservbyport(port: libc::c_int, proto: *const libc::c_char) -> *mut libc::servent;
}

struct ProtoName(u8);

impl fmt::Display for ProtoName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 as i32 {
            0 => "raw",
            IPPROTO_UDP => "udp",
            IPPROTO_TCP => "tcp",
            IPPROTO_SCTP => "sctp",
            IPPROTO_DCCP => "dccp",
            _ => "???",
        }
        .fmt(f)
    }
}

struct SockStateName(u8);

impl fmt::Display for SockStateName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match unsafe { mem::transmute(self.0) } {
            SS_UNKNOWN => "UNKNOWN",
            SS_ESTABLISHED => "ESTAB",
            SS_SYN_SENT => "SYN-SENT",
            SS_SYN_RECV => "SYN-RECV",
            SS_FIN_WAIT1 => "FIN-WAIT-1",
            SS_FIN_WAIT2 => "FIN-WAIT-2",
            SS_TIME_WAIT => "TIME-WAIT",
            SS_CLOSE => "UNCONN",
            SS_CLOSE_WAIT => "CLOSE-WAIT",
            SS_LAST_ACK => "LAST-ACK",
            SS_LISTEN => "LISTEN",
            SS_CLOSING => "CLOSING",
        }
        .fmt(f)
    }
}

struct SctpStateName(u8);

impl fmt::Display for SctpStateName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SctpState::*;

        match SctpState::try_from(self.0).unwrap() {
            SCTP_STATE_CLOSED => "CLOSED",
            SCTP_STATE_COOKIE_WAIT => "COOKIE_WAIT",
            SCTP_STATE_COOKIE_ECHOED => "COOKIE_ECHOED",
            SCTP_STATE_ESTABLISHED => "ESTAB",
            SCTP_STATE_SHUTDOWN_PENDING => "SHUTDOWN_PENDING",
            SCTP_STATE_SHUTDOWN_SENT => "SHUTDOWN_SENT",
            SCTP_STATE_SHUTDOWN_RECEIVED => "SHUTDOWN_RECEIVED",
            SCTP_STATE_SHUTDOWN_ACK_SENT => "ACK_SENT",
        }
        .fmt(f)
    }
}
