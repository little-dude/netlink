extern crate netlink_sys;

use netlink_sys::constants::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_sys::rtnl::{LinkFlags, LinkHeader, LinkLayerType, LinkMessage, Message, RtnlMessage};
use netlink_sys::{NetlinkFlags, Protocol, Socket, SocketAddr};

fn main() {
    let mut socket = Socket::new(Protocol::Route).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

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
    socket.send(&buf[..], 0).unwrap();

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;

    // we set the NLM_F_DUMP flag so we expect a multipart rx_packet in response.
    loop {
        let size = socket.recv(&mut receive_buffer[..], 0).unwrap();

        loop {
            let rx_packet = Message::from_bytes(&receive_buffer[offset..]).unwrap();
            println!("<<< {:?}", rx_packet);

            if *rx_packet.message() == RtnlMessage::Done {
                println!("Done!");
                return;
            }

            offset += rx_packet.length() as usize;
            // the header.length() check avoids infinite loops
            if offset == size || rx_packet.length() == 0 {
                offset = 0;
                break;
            }
        }
    }
}
