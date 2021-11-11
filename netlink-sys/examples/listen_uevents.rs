// Build:
//
// ```
// cd netlink-sys
// cargo run --example listen_uevents
//
// ```
//
// Run *as root*:
//
// ```
// find /sys -name uevent -exec sh -c 'echo add >"{}"' ';
// ```
//
// To generate events.

use std::process;

use netlink_sys::{protocols::NETLINK_KOBJECT_UEVENT, Socket, SocketAddr};

fn main() {
    let mut socket = Socket::new(NETLINK_KOBJECT_UEVENT).unwrap();
    let sa = SocketAddr::new(process::id(), 1);
    let mut buf = vec![0; 1024 * 8];

    socket.bind(&sa);

    loop {
        let n = socket.recv(&mut buf, 0).unwrap();
        let s = String::from_utf8_lossy(&buf[..n]);
        println!(">> {}", s);
    }
}
