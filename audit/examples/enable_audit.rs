extern crate audit;
extern crate futures;
extern crate netlink_sys;
extern crate tokio_core;

use audit::new_connection;
use futures::{Future, Stream};
use tokio_core::reactor::Core;

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
