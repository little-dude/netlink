#[macro_use]
extern crate log;

use structopt::StructOpt;

use netlink_packet::{
    sock_diag::{Extension, InetDiagRequest, SockDiagMessage, TcpStates},
    Emitable, NetlinkBuffer, NetlinkMessage, NetlinkPayload, Parseable,
};
use netlink_sys::{Protocol, Socket, SocketAddr};

#[derive(Debug, StructOpt)]
#[structopt(name = "netstat", about = "An example of print network connections.")]
struct Opt {
    /// display listening server sockets
    #[structopt(short = "l", long = "listening")]
    listening: bool,

    #[structopt(short = "a", long = "all")]
    all: bool,
}

fn main() {
    pretty_env_logger::init();

    let opts = Opt::from_args();

    debug!("parsed options: {:?}", opts);

    let mut socket = Socket::new(Protocol::SockDiag).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let families = [libc::AF_INET, libc::AF_INET6];
    let protocols = [libc::IPPROTO_TCP, libc::IPPROTO_UDP];

    for protocol in &protocols {
        if *protocol == libc::IPPROTO_TCP {
            println!("Proto Recv-Q Send-Q Local Address           Foreign Address         State")
        }

        for family in &families {
            let mut req = InetDiagRequest::new(*family as u8, *protocol as u8);

            match *protocol {
                libc::IPPROTO_TCP => {
                    req.extensions |= Extension::Info;

                    if opts.all {
                        req.states = TcpStates::All;
                    } else if opts.listening {
                        req.states = TcpStates::Listen;
                    } else {
                        req.states = TcpStates::Established;
                    }
                }
                libc::IPPROTO_UDP => {
                    if !(opts.all || opts.listening) {
                        continue;
                    }
                }
                _ => {}
            }

            let mut packet: NetlinkMessage = SockDiagMessage::InetDiag(req).into();

            packet.header.flags.set_dump().set_request();
            packet.header.sequence_number = 1;
            packet.finalize();

            let mut buf = vec![0; packet.header.length as usize];

            assert!(buf.len() == packet.buffer_len());
            packet.emit(&mut buf[..]);

            trace!(">>> {:?}", packet);
            socket.send(&buf[..], 0).unwrap();

            let mut receive_buffer = vec![0; 4096];
            let mut offset = 0;

            // we set the NLM_F_DUMP flag so we expect a multipart rx_packet in response.
            'next: loop {
                let size = socket.recv(&mut receive_buffer[..], 0).unwrap();

                loop {
                    let bytes = &receive_buffer[offset..];
                    // Note that we're parsing a NetlinkBuffer<&&[u8]>, NOT a NetlinkBuffer<&[u8]> here.
                    // This is important because Parseable<NetlinkMessage> is only implemented for
                    // NetlinkBuffer<&'buffer T>, where T implements AsRef<[u8] + 'buffer. This is not
                    // particularly user friendly, but this is a low level library anyway.
                    //
                    // Note also that the same could be written more explicitely with:
                    //
                    // let rx_packet =
                    //     <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(NetlinkBuffer::new(&bytes))
                    //         .unwrap();
                    //
                    let rx_packet: NetlinkMessage = NetlinkBuffer::new(&bytes).parse().unwrap();

                    trace!("<<< {:?}", rx_packet);

                    match rx_packet.payload {
                        NetlinkPayload::SockDiag(SockDiagMessage::InetSocks(ref sock)) => {
                            let is_ipv6 = sock.family == libc::AF_INET6 as u8;
                            let bind_any = if is_ipv6 { "[::]:*" } else { "0.0.0.0:*" };

                            println!(
                                "{}{}\t{:>4}   {:>4} {:<24}{:<24}{}",
                                match *protocol {
                                    libc::IPPROTO_TCP => "tcp",
                                    libc::IPPROTO_UDP => "udp",
                                    _ => "raw",
                                },
                                if is_ipv6 { "6" } else { "" },
                                sock.rqueue,
                                sock.wqueue,
                                if let Some(addr) = sock.id.src {
                                    addr.to_string()
                                } else {
                                    bind_any.to_owned()
                                },
                                if let Some(addr) = sock.id.dst {
                                    addr.to_string()
                                } else {
                                    bind_any.to_owned()
                                },
                                if *protocol == libc::IPPROTO_TCP {
                                    format!("{:?}", sock.state).split_off("TCP_".len())
                                } else {
                                    String::new()
                                },
                            )
                        }
                        NetlinkPayload::SockDiag(SockDiagMessage::UnixSocks(_)) => {}
                        _ => {}
                    }

                    if rx_packet.payload == NetlinkPayload::Done {
                        trace!("Done!");
                        break 'next;
                    }

                    offset += rx_packet.header.length as usize;
                    if offset == size || rx_packet.header.length == 0 {
                        offset = 0;
                        break;
                    }
                }
            }
        }
    }
}
