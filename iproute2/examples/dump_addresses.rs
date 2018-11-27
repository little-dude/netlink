extern crate futures;
extern crate iproute2;
extern crate tokio_core;

use futures::Future;
use iproute2::new_connection;
use tokio_core::reactor::Core;

fn main() {
    // Create a netlink connection for each request,
    // and a handle to send requests via each connection
    let (connection1, handle1) = new_connection().unwrap();
    let (connection2, handle2) = new_connection().unwrap();

    // The connections will run in an event loop
    let mut core = Core::new().unwrap();
    core.handle().spawn(connection1.map_err(|_| ()));
    core.handle().spawn(connection2.map_err(|_| ()));

    // Get the IP addresses for all links
    let addresses = handle1.address().get().execute();

    // Get the list of links
    let links = handle2.link().get().execute();

    let request = links.join(addresses).and_then(|(links, addresses)| {
        for addr in addresses {
            let ip = addr
                .address()
                .map(|a| a.to_string())
                .unwrap_or("".to_string());

            // find the corresponding link name using the address link index
            let link_name = links
                .iter()
                .find(|link| link.index() == addr.index())
                .map(|link| link.name().unwrap_or(""))
                .unwrap_or("");
            println!("{}\t{}\t{}", addr.index(), link_name, ip);
        }
        Ok(())
    });

    // Run the request on the event loop
    core.run(request).unwrap();
}
