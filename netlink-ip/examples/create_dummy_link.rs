extern crate futures;
extern crate netlink_ip;
extern crate tokio_core;

use std::thread::spawn;

use futures::Future;
use tokio_core::reactor::Core;

use netlink_ip::new_connection;

fn main() {
    let (connection, handle) = new_connection().unwrap();
    spawn(move || Core::new().unwrap().run(connection));
    handle
        .link()
        .add()
        .dummy("dummy-rs".into())
        .execute()
        .wait()
        .unwrap();
}
