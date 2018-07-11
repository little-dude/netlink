extern crate env_logger;
extern crate futures;
extern crate netlink_socket;
extern crate rtnetlink;

use futures::{Future, Sink, Stream};

use netlink_socket::{Protocol, SocketAddr, TokioSocket};
use rtnetlink::constants::{NLM_F_DUMP, NLM_F_REQUEST};
use rtnetlink::{
    LinkHeader, LinkMessage, NetlinkCodec, NetlinkFlags, NetlinkFramed, NetlinkMessage, RtnlMessage,
};

fn main() {
    env_logger::init();
    let mut socket = TokioSocket::new(Protocol::Route).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();
    let stream = NetlinkFramed::new(socket, NetlinkCodec::<NetlinkMessage>::new());

    let mut packet: NetlinkMessage =
        RtnlMessage::GetLink(LinkMessage::from_parts(LinkHeader::new(), vec![])).into();
    packet
        .header_mut()
        .set_flags(NetlinkFlags::from(NLM_F_DUMP | NLM_F_REQUEST))
        .set_sequence_number(1);
    packet.finalize();
    let mut buf = vec![0; packet.header().length() as usize];
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
