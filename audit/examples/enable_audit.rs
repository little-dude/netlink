extern crate audit;
extern crate env_logger;
extern crate futures;
extern crate netlink_sys;
extern crate tokio_core;

use audit::new_connection;
use futures::{Future, Stream};
use std::thread;
use std::time::Duration;
use tokio_core::reactor::Core;

// fn main() {
//     env_logger::init();
//     // Create a netlink connection, and a handle to send requests via this connection
//     let (connection, mut handle) = new_connection().unwrap();
//
//     // The connection will run in an event loop
//     let mut core = Core::new().unwrap();
//     core.handle().spawn(connection.map_err(|_| ()));
//
//     let req = handle.enable().and_then(|p| {
//         println!("{:?}", p);
//         thread::sleep(Duration::from_millis(600_000));
//         Ok(())
//     });
//
//     core.run(req).unwrap();
// }
fn main() {
    env_logger::init();
    let (mut connection, mut handle, messages) = new_connection().unwrap();
    connection
        .socket_mut()
        .add_membership(netlink_sys::constants::AUDIT_NLGRP_READLOG)
        .unwrap();

    let mut core = Core::new().unwrap();
    core.handle().spawn(connection.map_err(|_| ()));
    core.handle().spawn(handle.enable().map_err(|e| {
        println!("{:?}", e);
    }));
    core.run(messages.for_each(|m| {
        println!("{:?}", m);
        Ok(())
    }));
}
