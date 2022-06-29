// SPDX-License-Identifier: MIT

use rtnetlink::new_connection;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> Result<(), String> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let name = "my-ip-tun-1".to_string();
    let remote = Ipv4Addr::new(1, 2, 3, 4);
    let local = Ipv4Addr::new(0, 0, 0, 0);

    handle
        .link()
        .add()
        .ipip(name, remote, local)
        .ttl(64)
        .up()
        .execute()
        .await
        .map_err(|e| format!("{}", e))
}
