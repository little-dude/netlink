// SPDX-License-Identifier: MIT

//! In this example, we create a netlink connection, and send a request to retrieve the list of
//! rules. We receive a stream of rule messages that we just prints to the terminal.
use audit::{new_connection, Error, Handle};
use futures::stream::TryStreamExt;

#[tokio::main]
async fn main() -> Result<(), String> {
    let (connection, handle, _) = new_connection().map_err(|e| format!("{}", e))?;
    tokio::spawn(connection);
    list_rules(handle).await.map_err(|e| format!("{}", e))
}

async fn list_rules(mut handle: Handle) -> Result<(), Error> {
    let mut rules = handle.list_rules();
    while let Some(rule) = rules.try_next().await? {
        println!("{:?}", rule);
    }
    Ok(())
}
