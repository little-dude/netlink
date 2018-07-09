extern crate env_logger;
extern crate futures;
extern crate netlink_ip;
extern crate netlink_sys;
extern crate tokio_core;

use futures::Future;
use netlink_ip::new_connection;
use tokio_core::reactor::Core;

fn main() {
    env_logger::init();
    let mut core = Core::new().unwrap();
    let (connection, handle) = new_connection().unwrap();
    core.handle().spawn(connection.map_err(|_| ()));
    core.run(handle.link().list().and_then(|links| {
        println!("{:#?}", links);
        Ok(())
    })).unwrap();
}
