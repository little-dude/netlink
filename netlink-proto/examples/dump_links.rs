use futures::{Future, Sink, Stream};

use netlink_packet_route::{
    link::{LinkHeader, LinkMessage},
    RtnlMessage,
};

use netlink_proto::{
    packet::{
        header::flags::{NLM_F_DUMP, NLM_F_REQUEST},
        NetlinkFlags, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    },
    sys::{Protocol, SocketAddr, TokioSocket},
    NetlinkCodec, NetlinkFramed,
};

fn main() {
    let mut socket = TokioSocket::new(Protocol::Route).unwrap();
    // We could use the port number if we were interested in it.
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    // `NetlinkFramed<RtnlMessage>` wraps the socket and provides
    // Stream and Sink implementations for the messages.
    let stream = NetlinkFramed::new(socket, NetlinkCodec::<NetlinkMessage<RtnlMessage>>::new());

    // Create the payload for the request.
    let payload: NetlinkPayload<RtnlMessage> =
        RtnlMessage::GetLink(LinkMessage::from_parts(LinkHeader::new(), vec![])).into();

    // Create the header for the request
    let mut header = NetlinkHeader::new();
    header.flags = NetlinkFlags::from(NLM_F_DUMP | NLM_F_REQUEST);
    header.sequence_number = 1;

    // Create the netlink packet itself
    let mut packet = NetlinkMessage::new(header, payload);
    // `finalize` is important: it garantees the header is consistent
    // with the packet's payload. Having incorrect header can lead to
    // a panic when the message is serialized.
    packet.finalize();

    // Serialize the packet and send it
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..packet.buffer_len()]);
    println!(">>> {:?}", packet);
    let stream = stream.send((packet, SocketAddr::new(0, 0))).wait().unwrap();

    // Print all the incoming message (press ^C to exit)
    stream
        .for_each(|(packet, _addr)| {
            println!("<<< {:?}", packet);
            Ok(())
        })
        .wait()
        .unwrap();
}
