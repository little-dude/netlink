extern crate futures;
extern crate iproute2;
extern crate tokio_core;

use futures::Future;
use iproute2::new_connection;
use tokio_core::reactor::Core;

fn main() {
    let mut core = Core::new().unwrap();
    let (connection, handle) = new_connection().unwrap();
    core.handle().spawn(connection.map_err(|_| ()));
    core.run(handle.link().get().execute().and_then(|links| {
        println!("{:#?}", links);
        Ok(())
    })).unwrap();
}
