use std::thread::spawn;

use futures::{Future, Stream};
use tokio_core::reactor::Core;

use rtnetlink::new_connection;
use rtnetlink::packet::LinkNla;

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

    handle
        .link()
        .get()
        .execute()
        // Filter the link to keep the one with the wanted name
        .filter(|link_msg| {
            for nla in link_msg.nlas() {
                if let LinkNla::IfName(ref name) = nla {
                    return name == link_name;
                }
            }
            false
        })
        // Convert the stream into a future
        .collect()
        .map_err(|e| format!("{}", e))
        // Make sure we found 1 and only 1 link with the given name, and return it
        .and_then(|mut link_msgs| {
            if link_msgs.len() > 1 {
                Err(format!("Found multiple links named {}", link_name))
            } else if link_msgs.is_empty() {
                Err(format!("Link {} not found", link_name))
            } else {
                Ok(link_msgs.drain(..).next().unwrap())
            }
        })
        // Flush the addresses on the link
        .and_then(|link_msg| {
            handle
                .address()
                .flush(link_msg.header().index())
                .execute()
                .map(|_| println!("done"))
                .map_err(|e| format!("{}", e))
        })
        // Print the potential errors
        .or_else(|e| {
            eprintln!("{}", e);
            Ok(()) as Result<(), String>
        })
        .wait()
        .unwrap();
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
