use std::env;
use std::thread::spawn;

use futures::{Future, Stream};
use tokio_core::reactor::Core;

use rtnetlink::new_connection;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return usage();
    }
    let link_name = &args[1];

    // Create a connection and a handle to use it
    let (connection, handle) = new_connection().unwrap();

    // Spawn the connection in a background thread. All we need is the handle.
    spawn(move || Core::new().unwrap().run(connection));

    // Get the list of links
    let links = handle.link().get().execute().collect().wait().unwrap();

    for link in links {
        // Find the link with the name provided as argument, and set it down
        if link.name().unwrap() == link_name {
            println!("setting link {} down", link_name);
            let req = handle.link().set(link.index()).down();
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
    cargo run --example set_link_down -- <link name>

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd netlink-ip ; cargo build --example set_link_down

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./set_link_down <link_name>"
    );
}
