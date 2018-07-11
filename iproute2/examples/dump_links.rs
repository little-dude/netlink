extern crate futures;
extern crate iproute2;
extern crate tokio_core;

use futures::Future;
use iproute2::new_connection;
use tokio_core::reactor::Core;

fn main() {
    // Create a netlink connection, and a handle to send requests via this connection
    let (connection, handle) = new_connection().unwrap();

    // The connection will run in an event loop
    let mut core = Core::new().unwrap();
    core.handle().spawn(connection.map_err(|_| ()));

    // Create a netlink request
    let request = handle.link().get().execute().and_then(|links| {
        println!("{:#?}", links);
        Ok(())
    });

    // Run the request on the event loop
    core.run(request).unwrap();
}
