// SPDX-License-Identifier: MIT

// To run this example:
//   1) create a iptables/nft rules that send packet with group 1, for example:
//          sudo iptables -A INPUT -j NFLOG --nflog-group 1
//   2) build the example:
//          cargo build --example nflog
//   3) run it as root:
//          sudo ../target/debug/examples/nflog

use std::time::Duration;

use netlink_packet_netfilter::{
    constants::*,
    message::NetfilterMessage,
    nflog::{
        self,
        config::{ConfigCmd, ConfigFlags, ConfigMode, Timeout},
    },
    NetlinkMessage,
    NetlinkPayload,
};
use netlink_sys::{constants::NETLINK_NETFILTER, Socket};

fn main() {
    let mut receive_buffer = vec![0; 4096];

    // First, we bind the socket
    let mut socket = Socket::new(NETLINK_NETFILTER).unwrap();
    socket.bind_auto().unwrap();

    // Then we issue the PfBind command
    let packet = nflog::config::config_request(AF_INET, 0, vec![ConfigCmd::PfBind.into()]);
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    // And check there is no error
    let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
    let bytes = &receive_buffer[..size];
    let rx_packet = <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();
    println!("<<< {:?}", rx_packet);
    assert!(matches!(rx_packet.payload, NetlinkPayload::Ack(_)));

    // After that we issue a Bind command, to start receiving packets. We can also set various parameters at the same time
    let timeout: Timeout = Duration::from_millis(100).into();
    let packet = nflog::config::config_request(
        AF_INET,
        1,
        vec![
            ConfigCmd::Bind.into(),
            ConfigFlags::SEQ_GLOBAL.into(),
            ConfigMode::new_packet(16).into(),
            timeout.into(),
        ],
    );
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
    let bytes = &receive_buffer[..size];
    let rx_packet = <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();
    println!("<<< {:?}", rx_packet);
    assert!(matches!(rx_packet.payload, NetlinkPayload::Ack(_)));

    // And now we can receive the packets

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
