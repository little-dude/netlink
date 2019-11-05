use netlink_packet_route::{
    constants::*, nlas::neighbour::Nla, NeighbourMessage, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, RtnlMessage,
};
use netlink_sys::{Protocol, Socket, SocketAddr};
use std::net::Ipv4Addr;
use std::string::ToString;

fn main() {
    let mut socket = Socket::new(Protocol::Route).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut req = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_DUMP | NLM_F_REQUEST,
            ..Default::default()
        },
        payload: NetlinkPayload::from(RtnlMessage::GetNeighbour(NeighbourMessage::default())),
    };
    // IMPORTANT: call `finalize()` to automatically set the
    // `message_type` and `length` fields to the appropriate values in
    // the netlink header.
    req.finalize();

    let mut buf = vec![0; req.header.length as usize];
    req.serialize(&mut buf[..]);

    println!(">>> {:?}", req);
    socket.send(&buf[..], 0).unwrap();

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;

    let mut ipv4_entries = vec![];

    'outer: loop {
        let size = socket.recv(&mut receive_buffer[..], 0).unwrap();

        loop {
            let bytes = &receive_buffer[offset..];
            // Parse the message
            let msg: NetlinkMessage<RtnlMessage> = NetlinkMessage::deserialize(bytes).unwrap();

            match msg.payload {
                NetlinkPayload::Done => break 'outer,
                NetlinkPayload::InnerMessage(RtnlMessage::NewNeighbour(entry)) => {
                    if entry.header.family as u16 == AF_INET {
                        ipv4_entries.push(entry);
                    }
                }
                NetlinkPayload::Error(err) => {
                    eprintln!("Received a netlink error message: {:?}", err);
                    return;
                }
                _ => {}
            }

            offset += msg.header.length as usize;
            if offset == size || msg.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }

    if !ipv4_entries.is_empty() {
        println!("IPv4 entries");
        for entry in ipv4_entries {
            let state = state_str(entry.header.state);
            let mut dest: Option<Ipv4Addr> = None;
            let mut lladdr: Option<String> = None;
            for nla in entry.nlas {
                match nla {
                    Nla::Destination(addr) => {
                        // address family is AF_INET so we expect an ipv4
                        assert_eq!(addr.len(), 4);
                        dest = Some(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
                    }
                    Nla::LinkLocalAddress(addr) => {
                        // Assume MAC addresses for simplicity,
                        // although this might not always be the case
                        lladdr = Some(format!(
                            "{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}",
                            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
                        ));
                    }
                    _ => {}
                }
            }
            println!(
                "{:<20} {} ({})",
                dest.as_ref()
                    .map(ToString::to_string)
                    .unwrap_or("Unknown".into()),
                lladdr
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or("Unknown".into()),
                state
            );
        }
    }
}

fn state_str(value: u16) -> &'static str {
    match value {
        NUD_INCOMPLETE => "INCOMPLETE",
        NUD_REACHABLE => "REACHABLE",
        NUD_STALE => "STALE",
        NUD_DELAY => "DELAY",
        NUD_PROBE => "PROBE",
        NUD_FAILED => "FAILED",
        NUD_NOARP => "NOARP",
        NUD_PERMANENT => "PERMANENT",
        NUD_NONE => "NONE",
        _ => "UNKNOWN",
    }
}
