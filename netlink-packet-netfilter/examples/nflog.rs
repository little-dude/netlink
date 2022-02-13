// SPDX-License-Identifier: MIT

// To run this example:
//   1) create a iptables/nft rules that send packet with group 1, for example:
//          sudo iptables -A INPUT -j NFLOG --nflog-group 1
//   2) build the example:
//          cargo build --example nflog
//   3) run it as root:
//          sudo ../target/debug/examples/nflog

use std::{net::Ipv4Addr, time::Duration};

use byteorder::{ByteOrder, NetworkEndian};
use netlink_packet_netfilter::{
    constants::*,
    nflog::{
        config_request,
        nlas::{
            config::{ConfigCmd, ConfigFlags, ConfigMode, Timeout},
            packet::PacketNla,
        },
        NfLogMessage,
    },
    nl::{NetlinkMessage, NetlinkPayload},
    NetfilterMessage,
    NetfilterMessageInner,
};
use netlink_sys::{constants::NETLINK_NETFILTER, Socket};

fn get_packet_nlas(message: &NetlinkMessage<NetfilterMessage>) -> &[PacketNla] {
    if let NetlinkPayload::InnerMessage(NetfilterMessage {
        inner: NetfilterMessageInner::NfLog(NfLogMessage::Packet(nlas)),
        ..
    }) = &message.payload
    {
        nlas
    } else {
        &[]
    }
}

fn main() {
    let mut receive_buffer = vec![0; 4096];

    // First, we bind the socket
    let mut socket = Socket::new(NETLINK_NETFILTER).unwrap();
    socket.bind_auto().unwrap();

    // Then we issue the PfBind command
    let packet = config_request(AF_INET, 0, vec![ConfigCmd::PfBind.into()]);
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
    let packet = config_request(
        AF_INET,
        1,
        vec![
            ConfigCmd::Bind.into(),
            ConfigFlags::SEQ_GLOBAL.into(),
            ConfigMode::PACKET_MAX.into(),
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
    loop {
        match socket.recv(&mut &mut receive_buffer[..], 0) {
            Ok(size) => {
                let mut offset = 0;
                loop {
                    let bytes = &receive_buffer[offset..];

                    let rx_packet = <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();

                    for nla in get_packet_nlas(&rx_packet) {
                        if let PacketNla::Payload(payload) = nla {
                            let src = Ipv4Addr::from(NetworkEndian::read_u32(&payload[12..]));
                            let dst = Ipv4Addr::from(NetworkEndian::read_u32(&payload[16..]));
                            println!("Packet from {} to {}", src, dst);
                            break;
                        }
                    }

                    offset += rx_packet.header.length as usize;
                    if offset == size || rx_packet.header.length == 0 {
                        break;
                    }
                }
            }
            Err(e) => {
                println!("error while receiving packets: {:?}", e);
                break;
            }
        }
    }
}
