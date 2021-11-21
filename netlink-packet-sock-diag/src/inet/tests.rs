// SPDX-License-Identifier: MIT

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use crate::{
    constants::*,
    inet::{
        nlas::Nla,
        ExtensionFlags,
        InetRequest,
        InetRequestBuffer,
        InetResponse,
        InetResponseBuffer,
        InetResponseHeader,
        SocketId,
        StateFlags,
        Timer,
    },
    traits::{Emitable, Parseable},
};

lazy_static! {
    static ref REQ_UDP: InetRequest = InetRequest {
        family: AF_INET as u8,
        protocol: IPPROTO_UDP,
        extensions: ExtensionFlags::empty(),
        states: StateFlags::ESTABLISHED,
        socket_id: SocketId::new_v4(),
    };
}

#[rustfmt::skip]
static REQ_UDP_BUF: [u8; 56] = [
    0x02, // family (AF_INET)
    0x11, // protocol (IPPROTO_UDP)
    0x00, // extensions
    0x00, // padding
    0x02, 0x00, 0x00, 0x00, // states

    // socket id
    0x00, 0x00, // source port
    0x00, 0x00, // destination port
    // source address
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // destination address
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // interface id
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cookie
];

#[test]
fn parse_udp_req() {
    let parsed =
        InetRequest::parse(&InetRequestBuffer::new_checked(&&REQ_UDP_BUF[..]).unwrap()).unwrap();
    assert_eq!(parsed, *REQ_UDP);
}

#[test]
fn emit_udp_req() {
    assert_eq!(REQ_UDP.buffer_len(), 56);
    let mut buf = vec![0; REQ_UDP.buffer_len()];
    REQ_UDP.emit(&mut buf);
    assert_eq!(&buf[..], &REQ_UDP_BUF[..]);
}

lazy_static! {
    static ref RESP_TCP: InetResponse = InetResponse {
        header: InetResponseHeader {
            family: AF_INET as u8,
            state: TCP_ESTABLISHED,
            timer: Some(Timer::KeepAlive(Duration::from_millis(0x0000_6080))),
            recv_queue: 0,
            send_queue: 0,
            uid: 1000,
            inode: 0x0029_daa8,
            socket_id: SocketId {
                source_port: 60180,
                destination_port: 443,
                source_address: IpAddr::V4(Ipv4Addr::new(192, 168, 178, 60)),
                destination_address: IpAddr::V4(Ipv4Addr::new(172, 217, 23, 131)),
                interface_id: 0,
                cookie: [0x52, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            },
        },
        nlas: smallvec![Nla::Shutdown(0)],
    };
}

#[rustfmt::skip]
static RESP_TCP_BUF: [u8; 80] = [
    0x02, // family (AF_INET)
    0x01, // state (ESTABLISHED)
    0x02, // timer
    0x00, // retransmits

    // socket id
    0xeb, 0x14, // source port (60180)
    0x01, 0xbb, // destination port (443)
    // source ip (192.168.178.60)
    0xc0, 0xa8, 0xb2, 0x3c, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // destination ip (172.217.23.131)
    0xac, 0xd9, 0x17, 0x83, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // interface id
    0x52, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cookie

    0x80, 0x60, 0x00, 0x00, // expires
    0x00, 0x00, 0x00, 0x00, // receive queue
    0x00, 0x00, 0x00, 0x00, // send queue
    0xe8, 0x03, 0x00, 0x00, // uid
    0xa8, 0xda, 0x29, 0x00, // inode

    // nlas
    0x05, 0x00, // length = 5
    0x08, 0x00, // type = 8
    0x00, // value (0)
    0x00, 0x00, 0x00
];

#[test]
fn parse_tcp_resp() {
    let parsed =
        InetResponse::parse(&InetResponseBuffer::new_checked(&&RESP_TCP_BUF[..]).unwrap()).unwrap();
    assert_eq!(parsed, *RESP_TCP);
}

#[test]
fn emit_tcp_resp() {
    assert_eq!(RESP_TCP.buffer_len(), 80);
    let mut buf = vec![0; RESP_TCP.buffer_len()];
    RESP_TCP.emit(&mut buf);
    assert_eq!(&buf[..], &RESP_TCP_BUF[..]);
}
