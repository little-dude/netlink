extern crate futures;
extern crate rtnetlink;
extern crate tokio_core;

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

    let (connection, handle) = new_connection().unwrap();
    spawn(move || Core::new().unwrap().run(connection));

    // Get the list of links
    let links = handle.link().get().execute().collect().wait().unwrap();

    for link in links {
        // Find the link with the name provided as argument, and delete it
        if link.name().unwrap() == link_name {
            println!("deleting link {}", link_name);
            let req = handle.link().del(link.index());
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
    cargo run --example del_link -- <link name>

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd rtnetlink ; cargo build --example del_link

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./del_link <link_name>"
    );
}
