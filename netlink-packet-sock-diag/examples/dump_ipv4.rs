use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
    NetlinkHeader,
    NetlinkMessage,
    NetlinkPayload,
    SockDiagMessage,
};
use netlink_sys::{Protocol, Socket, SocketAddr};

fn main() {
    let mut socket = Socket::new(Protocol::SockDiag).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            ..Default::default()
        },
        payload: SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: IPPROTO_TCP.into(),
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id: SocketId::new_v4(),
        })
        .into(),
    };

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    // Before calling serialize, it is important to check that the buffer in which we're emitting is big
    // enough for the packet, other `serialize()` panics.
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf[..]);

    println!(">>> {:?}", packet);
    if let Err(e) = socket.send(&buf[..], 0) {
        println!("SEND ERROR {}", e);
        return;
    }

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    while let Ok(size) = socket.recv(&mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
            println!("<<< {:?}", rx_packet);

            match rx_packet.payload {
                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    println!("{:#?}", response);
                }
                NetlinkPayload::Done => {
                    println!("Done!");
                    return;
                }
                NetlinkPayload::Error(_) | NetlinkPayload::Overrun(_) | _ => return,
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}
