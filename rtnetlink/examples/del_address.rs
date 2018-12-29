use std::env;
use std::thread::spawn;

use futures::{Future, Stream};
use ipnetwork::IpNetwork;
use tokio_core::reactor::Core;

use rtnetlink::new_connection;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return usage();
    }
    let link_name = &args[1];
    let ip: IpNetwork = args[2].parse().unwrap_or_else(|_| {
        eprintln!("invalid address");
        std::process::exit(1);
    });

    // Create a netlink connection, and a handle to send requests via this connection
    let (connection, handle) = new_connection().unwrap();

    // The connection we run in its own thread
    spawn(move || Core::new().unwrap().run(connection));

    // Get the list of links
    let links = handle.link().get().execute().collect().wait().unwrap();

    for link in links {
        // Find the link with the name provided as argument
        if link.name().unwrap() == link_name {
            let req = handle.address().del(link.index(), ip);
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
    cargo run --example del_address -- <link_name> <ip_address>

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd rtnetlink ; cargo build --example del_address

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./del_address <link_name> <ip_address>"
    );
}
