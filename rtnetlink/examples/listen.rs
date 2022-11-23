// SPDX-License-Identifier: MIT

//! This example opens a netlink socket, registers for IPv4 and IPv6 routing changes, listens for
//! said changes and prints the received messages.

use futures::stream::StreamExt;

use netlink_proto::packet::NetlinkEvent;
use rtnetlink::{
    constants::{RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_ROUTE},
    new_connection,
    sys::{AsyncSocket, SocketAddr},
};

#[tokio::main]
async fn main() -> Result<(), String> {
    // Open the netlink socket
    let (mut connection, _, mut events) = new_connection().map_err(|e| format!("{}", e))?;

    // These flags specify what kinds of broadcast messages we want to listen for.
    let mgroup_flags = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

    // A netlink socket address is created with said flags.
    let addr = SocketAddr::new(0, mgroup_flags);
    // Said address is bound so new conenctions and thus new message broadcasts can be received.
    connection
        .socket_mut()
        .socket_mut()
        .bind(&addr)
        .expect("failed to bind");
    tokio::spawn(connection);

    while let Some(event) = events.next().await {
        match event {
            NetlinkEvent::Message((message, _)) => {
                let payload = message.payload;
                println!("Route change message - {:?}", payload);
            }
            NetlinkEvent::Overrun => println!("Netlink socket overrun. Some messages were lost"),
        }
    }
    Ok(())
}
