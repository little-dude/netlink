#[macro_use]
extern crate log;
extern crate env_logger;
extern crate futures;

// extern crate netlink_proto;
extern crate netlink_sys;
extern crate tokio_core;

use futures::{Async, Poll};
use futures::{Future, Stream};
use std::io;
use tokio_core::reactor::Core;

// use netlink_proto::codecs::NetlinkCodec;
// use netlink_proto::framed::NetlinkFramed;
use netlink_sys::constants::AUDIT_NLGRP_READLOG;
use netlink_sys::{Protocol, SocketAddr, TokioSocket};

// struct Socket(TokioSocket);
//
// fn main() {
//     env_logger::init();
//     let socket = Socket(TokioSocket::new(Protocol::Audit).unwrap());
//     let address = SocketAddr::new(0, AUDIT_NLGRP_READLOG);
//     info!("socket: connecting to {}", address);
//     socket.0.connect(&address).unwrap();
//     info!("socket: connected");
//     let mut core = Core::new().unwrap();
//     core.run(socket.map_err(|_| ())).unwrap();
// }
//
// impl Future for Socket {
//     type Item = ();
//     type Error = io::Error;
//
//     fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
//         info!("polling");
//         let mut v = vec![0; 4096];
//         while let Async::Ready(msg) = self.0.poll_recv(&mut v).unwrap() {
//             info!("message received: {} bytes", msg);
//         }
//         info!("not ready");
//         return Ok(Async::NotReady);
//     }
// }

use netlink_sys::Socket;

fn main() {
    env_logger::init();
    let mut socket = Socket::new(Protocol::Audit).unwrap();
    let address = SocketAddr::new(1234, 0);
    info!("socket: connecting to {}", address);
    // socket.connect(&address).unwrap();
    // socket.add_membership(AUDIT_NLGRP_READLOG);
    // info!("{:?}", socket.list_membership());
    let mut v = vec![0; 4096];
    loop {
        info!("{}", socket.recv(&mut v, 0).unwrap());
    }
}
