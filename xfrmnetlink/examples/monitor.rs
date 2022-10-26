// SPDX-License-Identifier: MIT

//! This example opens a netlink socket, listens for xfrm events, and prints the received messages.

use futures::stream::StreamExt;

use xfrmnetlink::{
    new_connection,
    proto::*,
    sys::{AsyncSocket, SocketAddr},
};

//use netlink_packet_xfrm::{
//    constants::*,
//    XfrmMessage,
//};

#[tokio::main]
async fn main() -> Result<(), String> {
    // Open the netlink socket
    let (mut connection, _, mut messages) = new_connection().map_err(|e| format!("{}", e))?;

    // Can specify various XFRMNLGRP_* flags to specify specific messages to listen for.
    let xfrmgrp_flags: u32 = u32::MAX;

    // A netlink socket address is created with said flags.
    let addr = SocketAddr::new(0, xfrmgrp_flags);

    // Said address is bound so new conenctions and thus new message broadcasts can be received.
    connection
        .socket_mut()
        .socket_mut()
        .bind(&addr)
        .expect("failed to bind");

    //connection.socket_mut().socket_mut().set_listen_all_namespaces(true).map_err(|e| format!("{}", e))?;

    tokio::spawn(connection);

    while let Some((message, _)) = messages.next().await {
        let payload = message.payload;
        if let NetlinkPayload::InnerMessage(xfrm_msg) = payload {
            // Could match on XfrmMessage enum variants to print something unique
            match xfrm_msg {
                //XfrmMessage::AddSa(_m) => {}
                _ => println!("XFRM event message - {:?}", xfrm_msg),
            };
        } else {
            println!("Other netlink message - {:?}", payload);
        }
    }
    Ok(())
}
