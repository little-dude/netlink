extern crate env_logger;
extern crate futures;
extern crate netlink_sys;

use futures::{Future, Sink, Stream};
use netlink_sys::constants::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_sys::rtnl::{LinkFlags, LinkHeader, LinkLayerType, LinkMessage, Message, RtnlMessage};
use netlink_sys::{NetlinkCodec, NetlinkFlags, NetlinkFramed, Protocol, SocketAddr, TokioSocket};

fn main() {
    env_logger::init();
    let mut socket = TokioSocket::new(Protocol::Route).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();
    let stream = NetlinkFramed::new(socket, NetlinkCodec::<Message>::new());

    let mut packet: Message = RtnlMessage::GetLink(LinkMessage {
        header: LinkHeader {
            address_family: 0, // AF_UNSPEC
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::new(),
            change_mask: LinkFlags::new(),
            index: 0,
        },
        nlas: vec![],
    }).into();
    packet.set_flags(NetlinkFlags::from(NLM_F_DUMP | NLM_F_REQUEST));
    packet.set_sequence_number(1);
    packet.finalize();
    let mut buf = vec![0; packet.length() as usize];
    packet.to_bytes(&mut buf[..]).unwrap();

    println!(">>> {:?}", packet);
    let stream = stream.send((packet, SocketAddr::new(0, 0))).wait().unwrap();

    stream
        .for_each(|(packet, _addr)| {
            println!("<<< {:?}", packet);
            Ok(())
        })
        .wait()
        .unwrap();
}
