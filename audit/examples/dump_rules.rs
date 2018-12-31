//! In this example, we create a netlink connection, and send a request to retrieve the list of
//! rules. We receive a stream of rule messages that we just prints to the terminal.
use futures::{Future, Stream};
use tokio_core::reactor::Core;

use audit::new_connection;

fn main() {
    env_logger::init();

    let mut core = Core::new().unwrap();

    // Open the netlink socket
    let (connection, mut handle, _) = new_connection().unwrap();

    // Spawn the netlink connection Future on the event loop.
    core.handle().spawn(connection.map_err(|_| ()));

    // Create the request
    let request = handle.list_rules().for_each(|rule_msg| {
        println!("{:?}", rule_msg);
        Ok(())
    });

    // Run the request
    if let Err(e) = core.run(request) {
        eprintln!("{}", e);
    } else {
        println!("done");
    }
}
