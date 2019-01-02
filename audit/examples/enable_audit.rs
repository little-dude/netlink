use netlink_sys;

use audit::new_connection;
use futures::{Future, Stream};
use std::thread::spawn;
use tokio_core::reactor::Core;

fn main() {
    env_logger::init();
    let (mut connection, mut handle, messages) = new_connection().unwrap();
    connection
        .socket_mut()
        .add_membership(netlink_sys::constants::AUDIT_NLGRP_READLOG)
        .unwrap();

    spawn(|| Core::new().unwrap().run(connection));
    handle.enable_events().wait().unwrap();
    messages
        .for_each(|m| {
            println!("{:?}", m);
            Ok(())
        })
        .wait()
        .unwrap();
}
