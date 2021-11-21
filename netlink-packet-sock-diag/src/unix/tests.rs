// SPDX-License-Identifier: MIT

use crate::{
    constants::*,
    traits::{Emitable, Parseable},
    unix::{
        nlas::Nla,
        ShowFlags,
        StateFlags,
        UnixRequest,
        UnixResponse,
        UnixResponseBuffer,
        UnixResponseHeader,
    },
};

lazy_static! {
    static ref SOCKET_INFO: UnixRequest = UnixRequest {
        state_flags: StateFlags::all(),
        inode: 0x1234,
        show_flags: ShowFlags::PEER,
        cookie: [0xff; 8]
    };
}

#[rustfmt::skip]
static SOCKET_INFO_BUF: [u8; 24] = [
    0x01, // family: AF_UNIX
    0x00, // protocol
    0x00, 0x00, // padding
    0x02, 0x04, 0x00, 0x00, // state_flags - 1 << TCP_ESTABLISHED | 1 << TCP_LISTEN
    0x34, 0x12, 0x00, 0x00, // inode number
    0x04, 0x00, 0x00, 0x00, // show_flags - UDIAG_SHOW_PEER
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // cookie
];

lazy_static! {
    static ref LISTENING: UnixResponse = UnixResponse {
        header: UnixResponseHeader {
            kind: SOCK_STREAM,
            state: TCP_LISTEN,
            inode: 20238,
            cookie: [0xa0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        },
        nlas: smallvec![
            Nla::Name("/tmp/.ICE-unix/1151".to_string()),
            Nla::ReceiveQueueLength(0, 128),
            Nla::Shutdown(0),
        ]
    };
}

#[rustfmt::skip]
static LISTENING_BUF: [u8; 60] = [
    0x01, // family: AF_UNIX
    0x01, // type: SOCK_STREAM
    0x0a, // state: TCP_LISTEN
    0x00, // padding
    0x0e, 0x4f, 0x00, 0x00, // inode number
    0xa0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cookie

    // NLAs
    0x18, 0x00, // length: 24
    0x00, 0x00, // type: UNIX_DIAG_NAME
    // value: /tmp/.ICE-unix/1151
    0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x2e, 0x49, 0x43, 0x45, 0x2d, 0x75, 0x6e, 0x69, 0x78, 0x2f, 0x31, 0x31, 0x35, 0x31, 0x00,

    0x0c, 0x00, // length: 12
    0x04, 0x00, // type: UNIX_DIAG_RQLEN
    // value: ReceiveQueueLength(0, 128)
    0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,

    0x05, 0x00, // length: 5
    0x06, 0x00, // type: UNIX_DIAG_SHUTDOWN
    0x00, // value: 0
    0x00, 0x00, 0x00 // padding
];

#[test]
fn parse_listening() {
    let parsed =
        UnixResponse::parse(&UnixResponseBuffer::new_checked(&&LISTENING_BUF[..]).unwrap())
            .unwrap();
    assert_eq!(parsed, *LISTENING);
}

#[test]
fn emit_listening() {
    assert_eq!(LISTENING.buffer_len(), 60);
    // Initialize the buffer with 0xff to check that padding bytes are
    // set to 0
    let mut buf = vec![0xff; LISTENING.buffer_len()];
    LISTENING.emit(&mut buf);
    assert_eq!(&buf[..], &LISTENING_BUF[..]);
}

lazy_static! {
    static ref ESTABLISHED: UnixResponse = UnixResponse {
        header: UnixResponseHeader {
            kind: SOCK_STREAM,
            state: TCP_ESTABLISHED,
            inode: 31927,
            cookie: [0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        },
        nlas: smallvec![
            Nla::Name("/run/user/1000/bus".to_string()),
            Nla::Peer(31062),
            Nla::ReceiveQueueLength(0, 0),
            Nla::Shutdown(0),
        ]
    };
}

#[rustfmt::skip]
static ESTABLISHED_BUF: [u8; 68] = [
    0x01, // family: AF_LOCAL
    0x01, // kind: SOCK_STREAM,
    0x01, // state: TCP_ESTABLISHED
    0x00, // padding
    0xb7, 0x7c, 0x00, 0x00, // inode: 31927
    0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cookie

    // NLAs

    0x17, 0x00, // length: 23
    0x00, 0x00, // type: UNIX_DIAG_NAME
    // value: /run/user/1000/bus
    0x2f, 0x72, 0x75, 0x6e, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2f, 0x31, 0x30, 0x30, 0x30, 0x2f, 0x62, 0x75, 0x73, 0x00,
    0x00, // padding

    0x08, 0x00, // length: 8
    0x02, 0x00, // type: UNIX_DIAG_PEER
    0x56, 0x79, 0x00, 0x00, // value: 31062

    0x0c, 0x00, // length: 12
    0x04, 0x00, // type: UNIX_DIAG_RQLEN
    // value: ReceiveQueueLength(0, 0)
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x05, 0x00, // length: 5
    0x06, 0x00, // type: UNIX_DIAG_SHUTDOWN
    0x00, 0x00, 0x00, 0x00 // value: 0
];

#[test]
fn parse_established() {
    let parsed =
        UnixResponse::parse(&UnixResponseBuffer::new_checked(&&ESTABLISHED_BUF[..]).unwrap())
            .unwrap();
    assert_eq!(parsed, *ESTABLISHED);
}

#[test]
fn emit_established() {
    assert_eq!(ESTABLISHED.buffer_len(), 68);
    let mut buf = vec![0xff; ESTABLISHED.buffer_len()];
    ESTABLISHED.emit(&mut buf);
    assert_eq!(&buf[..], &ESTABLISHED_BUF[..]);
}

#[test]
fn emit_socket_info() {
    assert_eq!(SOCKET_INFO.buffer_len(), 24);
    let mut buf = vec![0xff; SOCKET_INFO.buffer_len()];
    SOCKET_INFO.emit(&mut buf);
    assert_eq!(&buf[..], &SOCKET_INFO_BUF[..]);
}
