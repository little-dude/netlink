//! This example opens a netlink socket, enables audit events, and prints the events that are being
//! received.

use audit::new_connection;
use futures::stream::StreamExt;

#[async_std::main]
async fn main() -> Result<(), String> {
    let (connection, mut handle, mut messages) = new_connection().map_err(|e| format!("{}", e))?;

    async_std::task::spawn(connection);

    handle.enable_events().await.map_err(|e| format!("{}", e))?;

    env_logger::init();
    while let Some((msg, _)) = messages.next().await {
        println!("{:?}", msg);
    }
    Ok(())
}
