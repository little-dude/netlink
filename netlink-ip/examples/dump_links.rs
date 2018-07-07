extern crate netlink_ip;
extern crate netlink_sys;
extern crate tokio_core;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate futures;

use futures::Future;
use netlink_ip::new_connection;
use tokio_core::reactor::Core;

fn main() {
    env_logger::init();
    let mut core = Core::new().unwrap();
    let conn = new_connection(&core.handle()).unwrap();
    core.run(conn.link().list().and_then(|links| {
        println!("{:?}", links);
        Ok(())
    })).unwrap();
}
