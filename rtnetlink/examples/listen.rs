//! This example opens a netlink socket, registers for IPv4 and IPv6 routing changes, listens for
//! said changes and prints the received messages.

use futures::{Future, Stream};

use netlink_sys::{SocketAddr, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_ROUTE};
use rtnetlink::new_connection_with_messages;

fn main() {
    env_logger::init();

    // Open the netlink socket
    let (mut connection, _, messages) = new_connection_with_messages().unwrap();

    // These flags specify what kinds of broadcast messages we want to listen for.
    let mgroup_flags = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

    // A netlink socket address is created with said flags.
    let addr = SocketAddr::new(0, mgroup_flags);
    // Said address is bound so new conenctions and thus new message broadcasts can be received.
    connection.socket_mut().bind(&addr).expect("failed to bind");

    let msg_fut = messages.for_each(|m| {
        let payload = m.payload;
        println!("Route change message - {:?}", payload);
        Ok(())
    });

    let _ = connection
        .map_err(|e| eprintln!("Netlink connection error - {}", e))
        .join(msg_fut)
        .wait();
}
