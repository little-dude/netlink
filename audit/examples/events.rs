// SPDX-License-Identifier: MIT

//! This example opens a netlink socket, enables audit events, and prints the events that are being
//! received.

use audit::new_connection;
use futures::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), String> {
    let (connection, mut handle, mut events) = new_connection().map_err(|e| format!("{}", e))?;

    tokio::spawn(connection);
    handle.enable_events().await.map_err(|e| format!("{}", e))?;

    env_logger::init();
    while let Some(event) = events.next().await {
        println!("{event:?}");
    }
    Ok(())
}
