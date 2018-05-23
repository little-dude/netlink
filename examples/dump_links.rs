extern crate netlink;

use netlink::socket::sys::Socket;
use netlink::socket::{Protocol, SocketAddr};

use netlink::packet::rtnl::link::{
    LinkFlags, LinkLayerType, LinkMessage, LinkMessageBuffer, LinkNla,
};
use netlink::packet::{
    Buffer, Flags, Header, MessageType, Nla, HEADER_LEN, NLM_F_DUMP, NLM_F_REQUEST,
};

fn main() {
    let mut socket = Socket::new(Protocol::Route).unwrap();
    let port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let request = LinkMessage {
        address_family: 0, // AF_UNSPEC
        link_layer_type: LinkLayerType::Ether,
        flags: LinkFlags::new(),
    };

    let packet = Header {
        length: (request.buffer_len() + HEADER_LEN) as u32,
        message_type: MessageType::GetLink,
        flags: Flags::from(NLM_F_DUMP | NLM_F_REQUEST),
        sequence_number: 1,
        port_number: port_number,
    };

    let mut buf = vec![0; packet.length as usize];
    packet.emit(&mut buf[..]).unwrap();
    request.emit(&mut buf[packet.buffer_len()..]).unwrap();

    socket.send(&buf[..], 0).unwrap();

    let mut receive_buffer = vec![0; 4096];
    let mut first_message = true;
    let mut seq_number = 0;
    let mut offset = 0;

    // we set the NLM_F_DUMP flag so we expect a multipart message in response.
    loop {
        let size = socket.recv(&mut receive_buffer[..], 0).unwrap();

        loop {
            let header = Buffer::new_checked(&receive_buffer[offset..]).unwrap();

            if first_message {
                seq_number = header.sequence_number();
                first_message = false;
            }

            match header.message_type() {
                MessageType::NewLink if header.sequence_number() == seq_number => {
                    let newlink_message = LinkMessageBuffer::new(header.payload());
                    let parsed_newlink_header = LinkMessage::parse(&newlink_message);
                    println!("{:#?}", parsed_newlink_header);
                    for nla in newlink_message.nlas() {
                        let parsed_nla = LinkNla::parse(&nla.unwrap()).unwrap();
                        println!("{:#?}", parsed_nla);
                    }
                }
                MessageType::Error => panic!("received an error message!"),
                MessageType::Done if header.sequence_number() == seq_number => {
                    println!("done!");
                    return;
                }
                _ => println!("ignoring message: {:#?}", header.message_type()),
            }

            offset += header.length() as usize;

            // the header.length() check avoids infinite loops
            if offset == size || header.length() == 0 {
                offset = 0;
                break;
            }
        }
    }
}
