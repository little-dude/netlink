//! This example shows how to add an IP address to the given link, with minimal error handling.
//! You need to be root run this example.

use std::env;
use std::thread::spawn;

use futures::{Future, Stream};
use ipnetwork::IpNetwork;
use tokio_core::reactor::Core;

use netlink_packet_route::link::nlas::LinkNla;
use rtnetlink::{new_connection, ErrorKind};

fn main() {
    // Parse the arguments
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

    // Spawn the connection on the event loop
    spawn(move || Core::new().unwrap().run(connection));

    handle
        // The the "link" handle
        .link()
        // Create a "get" request from the link handle. We could tweak the request here, before
        // calling "execute()"
        .get()
        // Turn the request into a runnable future
        .execute()
        // The future is a stream of link message. We are interested only in a specific link, so we
        // filter out the other message.
        .filter(|link_msg| {
            for nla in &link_msg.nlas {
                if let LinkNla::IfName(ref name) = nla {
                    return name == link_name;
                }
            }
            false
        })
        .take(1)
        .for_each(|link_msg| {
            handle
                // Get an "address" handle
                .address()
                // Create an "add" request
                .add(link_msg.header.index, ip.ip(), ip.prefix())
                // Turn the request into a future
                .execute()
                .and_then(|_| {
                    println!("done");
                    Ok(())
                })
                .or_else(|e| match e.kind() {
                    // We handle permission denied errors gracefully
                    ErrorKind::NetlinkError(ref err_msg) if err_msg.code == -1 => {
                        eprintln!("permission denied!");
                        Ok(())
                    }
                    // but just propagate any other error
                    _ => Err(e),
                })
        })
        .wait()
        .unwrap();
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example add_address -- <link_name> <ip_address>

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd rtnetlink ; cargo build --example add_address

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./add_address <link_name> <ip_address>"
    );
}
