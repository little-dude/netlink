use netlink_packet_netfilter::{
    constants::*,
    message::NetfilterMessage,
    nflog::{
        self,
        config::{ConfigCmd, ConfigFlags, ConfigMode},
    },
    NetlinkMessage,
    NetlinkPayload,
};
use netlink_sys::{constants::NETLINK_NETFILTER, Socket};

fn main() {
    let mut socket = Socket::new(NETLINK_NETFILTER).unwrap();
    socket.bind_auto().unwrap();

    let packet = nflog::config::config_request(AF_INET, 0, vec![ConfigCmd::PfBind.into()]);
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();
    // TODO: check the response

    let packet = nflog::config::config_request(
        AF_INET,
        1,
        vec![
            ConfigCmd::Bind.into(),
            ConfigFlags::SEQ_GLOBAL.into(),
            ConfigMode::new_packet(16).into(),
        ],
    );
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();
    // TODO: check the response

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;

    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];

            let rx_packet = <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();
            println!("<<< {:?}", rx_packet);

            match rx_packet.payload {
                NetlinkPayload::Error(_) | NetlinkPayload::Overrun(_) => return,
                _ => (),
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}
