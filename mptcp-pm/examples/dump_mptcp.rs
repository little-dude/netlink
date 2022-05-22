// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(get_addresses());
}

async fn get_addresses() {
    let (connection, handle, _) = mptcp_pm::new_connection().unwrap();
    tokio::spawn(connection);

    let mut address_handle = handle.address().get().execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = address_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{:?}", msg);
    }

    let mut limits_handle = handle.limits().get().execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = limits_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{:?}", msg);
    }
}
