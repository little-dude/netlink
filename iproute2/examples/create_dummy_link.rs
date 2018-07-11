extern crate futures;
extern crate iproute2;
extern crate tokio_core;

use std::thread::spawn;

use futures::Future;
use tokio_core::reactor::Core;

use iproute2::new_connection;

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
