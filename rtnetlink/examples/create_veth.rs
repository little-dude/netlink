use std::thread::spawn;

use futures::Future;
use tokio_core::reactor::Core;

use rtnetlink::{new_connection, ErrorKind};

fn main() {
    // Create a netlink connection, and a handle to send requests via this connection
    let (connection, handle) = new_connection().unwrap();

    // The connection we run in its own thread
    spawn(move || Core::new().unwrap().run(connection));

    // Create a request to create the veth pair
    handle
        .link()
        .add()
        .veth("veth-rs-1".into(), "veth-rs-2".into())
        .execute()
        .wait()
        .map(|()| println!("done!"))
        .or_else(|e| match e.kind() {
            ErrorKind::NetlinkError(ref err_msg) if err_msg.code == -1 => {
                eprintln!("permission denied!");
                Ok(())
            }
            _ => Err(e),
        })
        .unwrap()
}
