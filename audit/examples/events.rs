//! This example opens a netlink socket, enables audit events, and prints the events that are being
//! received.
use std::thread::spawn;

use audit::new_connection;
use futures::{Future, Stream};
use tokio_core::reactor::Core;

/// Unused multicast group for audit
pub const AUDIT_NLGRP_NONE: u32 = 0;
/// Multicast group to listen for audit events
pub const AUDIT_NLGRP_READLOG: u32 = 1;

fn main() {
    env_logger::init();

    // Open the netlink socket
    let (mut connection, mut handle, messages) = new_connection().unwrap();

    // Add membership for the multicast group that receives event
    connection
        .socket_mut()
        .add_membership(AUDIT_NLGRP_READLOG)
        .unwrap();

    // Start the connection in the background
    spawn(|| Core::new().unwrap().run(connection));

    // Enable events
    handle.enable_events().wait().unwrap();

    // Print the events as they arrive
    messages
        .for_each(|m| {
            println!("{:?}", m);
            Ok(())
        })
        .wait()
        .unwrap();
}
