extern crate futures;
extern crate rtnetlink;
extern crate tokio_core;

use std::thread::spawn;

use futures::{Future, Stream};
use tokio_core::reactor::Core;

use rtnetlink::new_connection;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return usage();
    }
    let link_name = &args[1];

    // Create a netlink connection, and a handle to send requests via this connection
    let (connection, handle) = new_connection().unwrap();

    // The connection we run in its own thread
    spawn(move || Core::new().unwrap().run(connection));

    // Get the list of links
    let links = handle.link().get().execute().collect().wait().unwrap();

    for link in links {
        // Find the link with the name provided as argument
        if link.name().unwrap() == link_name {
            // Flush all addresses on the given link
            let req = handle.address().flush(link.index());
            match req.execute().wait() {
                Ok(()) => println!("done"),
                Err(e) => eprintln!("error: {}", e),
            }
            return;
        }
    }
    eprintln!("link {} not found", link_name);
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example flush_addresses -- <link_name>

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd rtnetlink ; cargo build --example flush_addresses

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./flush_addresses <link_name>"
    );
}
