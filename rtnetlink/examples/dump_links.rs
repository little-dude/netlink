



use futures::{Future, Stream};
use rtnetlink::new_connection;
use tokio_core::reactor::Core;

fn main() {
    // Create a netlink connection, and a handle to send requests via this connection
    let (connection, handle) = new_connection().unwrap();

    // The connection will run in an event loop
    let mut core = Core::new().unwrap();
    core.handle().spawn(connection.map_err(|_| ()));

    // Create a netlink request
    let request = handle.link().get().execute().for_each(|link| {
        println!("{:#?}", link);
        Ok(())
    });

    // Run the request on the event loop
    core.run(request).unwrap();
}
