use std::thread::spawn;

use futures::Future;
use tokio_core::reactor::Core;

use rtnetlink::new_connection;

fn main() {
    // Create a netlink connection, and a handle to send requests via this connection
    let (connection, handle) = new_connection().unwrap();

    // The connection we run in its own thread
    spawn(move || Core::new().unwrap().run(connection));

    // Create a request to create the veth pair
    println!(
        "{:#?}",
        handle
            .link()
            .add()
            .veth("veth-rs-1".into(), "veth-rs-2".into())
            // Execute the request, and wait for it to finish
            .execute()
            .wait()
    );
}
